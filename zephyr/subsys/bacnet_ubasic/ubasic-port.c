/**
 * @file
 * @brief uBASIC-Plus porting layer for the uBASIC-Plus interpreter - Zephyr
 * @date 2026
 * @copyright SPDX-License-Identifier: MIT
 *
 * Ported from bacnet-stack's ports/stm32f4xx/ubasic-port.c reference
 * implementation. The BACnet object create/read/write callbacks are fully
 * portable and carried over unchanged (they only call the bacnet-stack
 * object API, no STM32-specific code). The hardware callbacks
 * (GPIO/ADC/PWM/hardware-events/serial) are left as explicit no-op stubs,
 * same as the reference already did for its own serial callbacks - this
 * board's real GPIO/ADC wiring (via Zephyr's own driver APIs, e.g.
 * <zephyr/drivers/gpio.h>/<zephyr/drivers/adc.h>) is a separate, later
 * step once a specific board's pin usage is decided, not invented here.
 * The random-number and EEPROM-store callbacks use Zephyr-appropriate
 * replacements (sys_rand32_get() instead of a hand-rolled rand() mixer;
 * the "EEPROM" store/recall is still just a volatile RAM scratch buffer
 * as in the reference, despite the name - real NVS-backed persistence is
 * deferred, tracked in [[project_ubasic_zephyr_port]]).
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>
#include "bacnet/basic/object/ai.h"
#include "bacnet/basic/object/ao.h"
#include "bacnet/basic/object/av.h"
#include "bacnet/basic/object/bi.h"
#include "bacnet/basic/object/bo.h"
#include "bacnet/basic/object/bv.h"
#include "bacnet/basic/object/device.h"
#include "bacnet/basic/object/ms-input.h"
#include "bacnet/basic/object/mso.h"
#include "bacnet/basic/object/msv.h"
#include "bacnet/basic/program/ubasic/ubasic.h"
#include "bacnet/basic/sys/mstimer.h"
#include "bacnet/wp.h"

#if defined(UBASIC_SCRIPT_HAVE_PRINT_TO_SERIAL)
/**
 * @brief Write a buffer to the serial port - this is uBASIC's only output
 *  path, used for both `println`/`print` script output and its own
 *  tokenizer/parse-error messages (ubasic.c's token_error_print()). Routed
 *  to printk() rather than left as a no-op: a stubbed-out serial_write is
 *  exactly what made an early parse-error bug in the embedded demo script
 *  invisible (the interpreter halted with no visible reason). A real
 *  per-board UART/console target is still a @todo, but printk() at least
 *  makes script output and errors show up in the device log in the
 *  meantime.
 * @param msg Pointer to the buffer to write - not necessarily
 *  null-terminated, only `n` bytes are valid
 * @param n Number of bytes to write
 */
static void serial_write(const char *msg, uint16_t n)
{
    printk("%.*s", (int)n, msg);
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_INPUT_FROM_SERIAL)
/**
 * @brief Return the next byte from the input stream
 * @return next byte, or EOF(-1) if no byte is available
 * @todo wire to a real Zephyr console/UART once a target board is chosen
 */
static int serial_getc(void)
{
    return -1;
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_HARDWARE_EVENTS)
static uint32_t Event_Mask;

/**
 * @brief Hardware event status bit
 * @param bit Event bit
 * @return 1 if the event is set, 0 otherwise
 */
static int8_t hw_event(uint8_t bit)
{
    if (bit < 32) {
        if (Event_Mask & (1UL << bit)) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Clear a hardware event state bit
 * @param bit Event bit
 */
static void hw_event_clear(uint8_t bit)
{
    if (bit < 32) {
        Event_Mask &= ~(1UL << bit);
    }
}

/**
 * @brief Set a hardware event state bit - the external-facing half of the
 *  flag()/hw_event() mechanism (declared in ubasic-port.h, not
 *  program-ubasic.h, since this is hardware-facing, not Program-object
 *  lifecycle). Deliberately NOT wired to a real GPIO interrupt: this app's
 *  button is already polled and debounced every main-loop pass
 *  (BACnet_Device_Task_Handler(), CONFIG_BACNET_BASIC_SERVER_KSLEEP=1, so
 *  effectively every ~1ms) - a real ISR would just re-implement that same
 *  debounce with none of the latency/reliability benefit, and would need
 *  atomics for Event_Mask since an ISR is genuinely concurrent with the
 *  thread that reads it here; this setter runs on the exact same
 *  cooperative thread as hw_event()/hw_event_clear() (both only ever
 *  called from ubasic_run_program(), itself only ever called from
 *  Program_UBASIC_Task()/Program_Timer(), all on the one main-loop thread),
 *  so no synchronization is needed at all.
 * @param bit Event bit (0-31)
 */
void ubasic_port_hw_event_set(uint8_t bit)
{
    if (bit < 32) {
        Event_Mask |= (1UL << bit);
    }
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_STORE_VARS_IN_FLASH)
/* NOTE: despite the name, this is a volatile RAM scratch buffer, same as
 * the reference implementation - it does NOT survive a reboot. Real
 * NVS-backed persistence is deferred (see [[project_ubasic_zephyr_port]]). */
static uint8_t EEPROM_Buffer[256];

static size_t
eepromRead(uint16_t start_address, uint8_t *buffer, uint16_t length)
{
    size_t bytes_read = 0;
    uint16_t i = 0;

    for (i = 0; i < length; i++) {
        if (start_address + i < sizeof(EEPROM_Buffer)) {
            buffer[i] = EEPROM_Buffer[start_address + i];
            bytes_read++;
        } else {
            break;
        }
    }

    return bytes_read;
}

static size_t
eepromWrite(uint16_t start_address, uint8_t *buffer, uint16_t length)
{
    size_t bytes_written = 0;
    uint16_t i = 0;

    for (i = 0; i < length; i++) {
        if (start_address + i < sizeof(EEPROM_Buffer)) {
            EEPROM_Buffer[start_address + i] = buffer[i];
            bytes_written++;
        } else {
            break;
        }
    }

    return bytes_written;
}

#define UBASIC_FLASH_PAGE_SIZE 256

/**
 * @brief Write a variable to the (RAM-backed, non-persistent) store
 */
static void variable_write(
    uint8_t Name, uint8_t vartype, uint8_t datalen_bytes, uint8_t *dataptr)
{
    uint16_t start_address = Name * UBASIC_FLASH_PAGE_SIZE;
    uint8_t buffer[UBASIC_FLASH_PAGE_SIZE];

    buffer[0] = vartype;
    buffer[1] = datalen_bytes;
    for (uint8_t i = 0; i < datalen_bytes; i++) {
        buffer[i + 2] = dataptr[i];
    }
    eepromWrite(start_address, buffer, datalen_bytes + 2);
}

/**
 * @brief Read a variable from the (RAM-backed, non-persistent) store
 */
static void
variable_read(uint8_t Name, uint8_t vartype, uint8_t *dataptr, uint8_t *datalen)
{
    uint8_t buffer[UBASIC_FLASH_PAGE_SIZE] = { 0 };
    uint16_t start_address = Name * UBASIC_FLASH_PAGE_SIZE;

    eepromRead(start_address, buffer, UBASIC_FLASH_PAGE_SIZE);
    if (buffer[0] == vartype) {
        *datalen = buffer[1];
        for (uint8_t i = 0; i < *datalen; i++) {
            dataptr[i] = buffer[i + 2];
        }
    } else {
        *datalen = 0;
    }
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_RANDOM_NUMBER_GENERATOR)
/**
 * @brief Generate a random number using Zephyr's entropy-backed RNG
 * @param size Size of the random number in bits (unused - sys_rand32_get()
 *  always returns a full 32-bit value; callers mask/scale as needed, same
 *  contract the reference implementation's own bit-scrounging loop had)
 * @return Random 32-bit value
 */
static uint32_t random_uint32(uint8_t size)
{
    (void)size;
    return sys_rand32_get();
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_PWM_CHANNELS)
static int32_t dutycycle_pwm_ch[UBASIC_SCRIPT_HAVE_PWM_CHANNELS];

/**
 * @todo wire to real Zephyr PWM (<zephyr/drivers/pwm.h>) once a target
 *  board is chosen
 */
static void pwm_config(uint16_t psc, uint16_t per)
{
    (void)psc;
    (void)per;
}

static void pwm_write(uint8_t ch, int32_t dutycycle)
{
    if (ch < UBASIC_SCRIPT_HAVE_PWM_CHANNELS) {
        dutycycle_pwm_ch[ch] = dutycycle;
    }
}

static int32_t pwm_read(uint8_t ch)
{
    if (ch < UBASIC_SCRIPT_HAVE_PWM_CHANNELS) {
        return dutycycle_pwm_ch[ch];
    }
    return 0;
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_ANALOG_READ)
/**
 * @todo wire to real Zephyr ADC (<zephyr/drivers/adc.h>) once a target
 *  board is chosen
 */
static void adc_config(uint8_t sampletime, uint8_t nreads)
{
    (void)sampletime;
    (void)nreads;
}

static int32_t adc_read(uint8_t channel)
{
    (void)channel;
    return 0;
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_GPIO_CHANNELS)
/**
 * @todo wire to real Zephyr GPIO (<zephyr/drivers/gpio.h>) once a target
 *  board is chosen
 */
static void gpio_config(uint8_t ch, int8_t mode, uint8_t freq)
{
    (void)ch;
    (void)mode;
    (void)freq;
}

static void gpio_write(uint8_t ch, uint8_t pin_state)
{
    (void)ch;
    (void)pin_state;
}

static int32_t gpio_read(uint8_t ch)
{
    (void)ch;
    return 0;
}
#endif

#if defined(UBASIC_SCRIPT_HAVE_BACNET)
/**
 * @brief strdup() is a POSIX extension not guaranteed to be declared by
 *  every Zephyr libc configuration without a feature-test macro that
 *  varies by libc/board - avoid the dependency entirely with a small local
 *  equivalent instead of relying on a specific build's libc config.
 */
static char *ubasic_port_strdup(const char *s)
{
    size_t len;
    char *copy;

    if (!s) {
        return NULL;
    }
    len = strlen(s) + 1;
    copy = malloc(len);
    if (copy) {
        memcpy(copy, s, len);
    }

    return copy;
}

/**
 * @brief Create a BACnet object - fully portable, unchanged from reference
 *  except strdup() -> ubasic_port_strdup(), see that function's comment
 * @param object_type Object type
 * @param instance Object instance
 * @param object_name Object name
 */
static void
bacnet_create_object(uint16_t object_type, uint32_t instance, char *object_name)
{
    uint32_t r;

    switch (object_type) {
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_INPUT)
        case OBJECT_ANALOG_INPUT:
            if (!Analog_Input_Valid_Instance(instance)) {
                r = Analog_Input_Create(instance);
                if (r == instance) {
                    Analog_Input_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_OUTPUT)
        case OBJECT_ANALOG_OUTPUT:
            if (!Analog_Output_Valid_Instance(instance)) {
                r = Analog_Output_Create(instance);
                if (r == instance) {
                    Analog_Output_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_VALUE)
        case OBJECT_ANALOG_VALUE:
            if (!Analog_Value_Valid_Instance(instance)) {
                r = Analog_Value_Create(instance);
                if (r == instance) {
                    Analog_Value_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_INPUT)
        case OBJECT_BINARY_INPUT:
            if (!Binary_Input_Valid_Instance(instance)) {
                r = Binary_Input_Create(instance);
                if (r == instance) {
                    Binary_Input_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_OUTPUT)
        case OBJECT_BINARY_OUTPUT:
            if (!Binary_Output_Valid_Instance(instance)) {
                r = Binary_Output_Create(instance);
                if (r == instance) {
                    Binary_Output_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_VALUE)
        case OBJECT_BINARY_VALUE:
            if (!Binary_Value_Valid_Instance(instance)) {
                r = Binary_Value_Create(instance);
                if (r == instance) {
                    Binary_Value_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_INPUT)
        case OBJECT_MULTI_STATE_INPUT:
            if (!Multistate_Input_Valid_Instance(instance)) {
                r = Multistate_Input_Create(instance);
                if (r == instance) {
                    Multistate_Input_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_OUTPUT)
        case OBJECT_MULTI_STATE_OUTPUT:
            if (!Multistate_Output_Valid_Instance(instance)) {
                r = Multistate_Output_Create(instance);
                if (r == instance) {
                    Multistate_Output_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_VALUE)
        case OBJECT_MULTI_STATE_VALUE:
            if (!Multistate_Value_Valid_Instance(instance)) {
                r = Multistate_Value_Create(instance);
                if (r == instance) {
                    Multistate_Value_Name_Set(instance, ubasic_port_strdup(object_name));
                }
            }
            break;
#endif
        default:
            break;
    }
    (void)r;
}

/**
 * @brief Write a property to a BACnet object - fully portable, unchanged
 *  from reference. NOTE: property_id is already a real parameter here -
 *  only PROP_PRESENT_VALUE is handled below, and priority is hardcoded to
 *  BACNET_MAX_PRIORITY for commandable objects. Extending this to accept
 *  an arbitrary property id + priority (BACQL's one real advantage over
 *  uBASIC's own bac_read/bac_write) is deferred - see
 *  [[project_bacql_zephyr_port_archived]].
 * @param object_type Object type
 * @param instance Object instance
 * @param property_id Property ID
 * @param value Property value
 */
static void bacnet_write_property(
    uint16_t object_type,
    uint32_t instance,
    uint32_t property_id,
    UBASIC_VARIABLE_TYPE value)
{
    BACNET_BINARY_PV value_binary = BINARY_INACTIVE;
    BACNET_ERROR_CLASS error_class = ERROR_CLASS_PROPERTY;
    BACNET_ERROR_CODE error_code = ERROR_CODE_OTHER;

    switch (object_type) {
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_INPUT)
        case OBJECT_ANALOG_INPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                Analog_Input_Present_Value_Set(
                    instance, fixedpt_tofloat(value));
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_OUTPUT)
        case OBJECT_ANALOG_OUTPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                Analog_Output_Present_Value_Set(
                    instance, fixedpt_tofloat(value), BACNET_MAX_PRIORITY);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_VALUE)
        case OBJECT_ANALOG_VALUE:
            if (property_id == PROP_PRESENT_VALUE) {
                Analog_Value_Present_Value_Set(
                    instance, fixedpt_tofloat(value), BACNET_MAX_PRIORITY);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_INPUT)
        case OBJECT_BINARY_INPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                if (fixedpt_toint(value) != 0) {
                    value_binary = BINARY_ACTIVE;
                }
                Binary_Input_Present_Value_Set(instance, value_binary);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_OUTPUT)
        case OBJECT_BINARY_OUTPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                if (fixedpt_toint(value) != 0) {
                    value_binary = BINARY_ACTIVE;
                }
                /* _Write(), not _Set() - _Set() only updates the priority
                 * array and does NOT fire Write_Present_Value_Callback, so
                 * a script's write would silently never reach a physical
                 * output wired through that callback (e.g. an LED) - see
                 * [[project_ubasic_zephyr_port]] for the story */
                Binary_Output_Present_Value_Write(
                    instance, value_binary, BACNET_MAX_PRIORITY, &error_class,
                    &error_code);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_VALUE)
        case OBJECT_BINARY_VALUE:
            if (property_id == PROP_PRESENT_VALUE) {
                if (fixedpt_toint(value) != 0) {
                    value_binary = BINARY_ACTIVE;
                }
                Binary_Value_Present_Value_Set(instance, value_binary);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_INPUT)
        case OBJECT_MULTI_STATE_INPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                Multistate_Input_Present_Value_Set(
                    instance, fixedpt_toint(value));
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_OUTPUT)
        case OBJECT_MULTI_STATE_OUTPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                Multistate_Output_Present_Value_Set(
                    instance, fixedpt_toint(value), BACNET_MAX_PRIORITY);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_VALUE)
        case OBJECT_MULTI_STATE_VALUE:
            if (property_id == PROP_PRESENT_VALUE) {
                Multistate_Value_Present_Value_Set(
                    instance, fixedpt_toint(value));
            }
            break;
#endif
        default:
            break;
    }
    (void)value_binary;
    (void)error_class;
    (void)error_code;
}

/**
 * @brief Read a property from a BACnet object - fully portable, unchanged
 *  from reference (same PROP_PRESENT_VALUE-only scope as the write side).
 * @param object_type Object type
 * @param instance Object instance
 * @param property_id Property ID
 * @return Property value
 */
static UBASIC_VARIABLE_TYPE bacnet_read_property(
    uint16_t object_type, uint32_t instance, uint32_t property_id)
{
    UBASIC_VARIABLE_TYPE value = 0;
    float value_float = 0.0;
    BACNET_BINARY_PV value_binary = BINARY_INACTIVE;

    switch (object_type) {
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_INPUT)
        case OBJECT_ANALOG_INPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                value_float = Analog_Input_Present_Value(instance);
                value = fixedpt_fromfloat(value_float);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_OUTPUT)
        case OBJECT_ANALOG_OUTPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                value_float = Analog_Output_Present_Value(instance);
                value = fixedpt_fromfloat(value_float);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_ANALOG_VALUE)
        case OBJECT_ANALOG_VALUE:
            if (property_id == PROP_PRESENT_VALUE) {
                value_float = Analog_Value_Present_Value(instance);
                value = fixedpt_fromfloat(value_float);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_INPUT)
        case OBJECT_BINARY_INPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                value_binary = Binary_Input_Present_Value(instance);
                value =
                    fixedpt_fromint((value_binary == BINARY_ACTIVE) ? 1 : 0);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_OUTPUT)
        case OBJECT_BINARY_OUTPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                value_binary = Binary_Output_Present_Value(instance);
                value =
                    fixedpt_fromint((value_binary == BINARY_ACTIVE) ? 1 : 0);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_BINARY_VALUE)
        case OBJECT_BINARY_VALUE:
            if (property_id == PROP_PRESENT_VALUE) {
                value_binary = Binary_Value_Present_Value(instance);
                value =
                    fixedpt_fromint((value_binary == BINARY_ACTIVE) ? 1 : 0);
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_INPUT)
        case OBJECT_MULTI_STATE_INPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                value =
                    fixedpt_fromint(Multistate_Input_Present_Value(instance));
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_OUTPUT)
        case OBJECT_MULTI_STATE_OUTPUT:
            if (property_id == PROP_PRESENT_VALUE) {
                value =
                    fixedpt_fromint(Multistate_Output_Present_Value(instance));
            }
            break;
#endif
#if defined(CONFIG_BACNET_BASIC_OBJECT_MULTISTATE_VALUE)
        case OBJECT_MULTI_STATE_VALUE:
            if (property_id == PROP_PRESENT_VALUE) {
                value =
                    fixedpt_fromint(Multistate_Value_Present_Value(instance));
            }
            break;
#endif
        default:
            break;
    }
    (void)value_float;
    (void)value_binary;

    return value;
}
#endif

#if (                                              \
    defined(UBASIC_SCRIPT_HAVE_TICTOC_CHANNELS) || \
    defined(UBASIC_SCRIPT_HAVE_SLEEP) ||           \
    defined(UBASIC_SCRIPT_HAVE_INPUT_FROM_SERIAL))
/**
 * @brief mstimer_now() is declared to return `unsigned long` (mstimer.h),
 *  but the ubasic_data callback slot it's assigned to is typed
 *  `uint32_t (*)(void)` - same width on this target, but a distinct type,
 *  so a direct assignment is a real -Wincompatible-pointer-types build
 *  error here (apparently just a warning on whatever build the
 *  ports/stm32f4xx reference was last compiled with). A thin wrapper
 *  avoids both the type mismatch and a blind function-pointer cast.
 */
static uint32_t mstimer_now_u32(void)
{
    return (uint32_t)mstimer_now();
}
#endif

/**
 * @brief Initialize the hardware/BACnet drivers for one uBASIC instance
 * @param data Pointer to the ubasic data structure
 */
void ubasic_port_init(struct ubasic_data *data)
{
#if (                                              \
    defined(UBASIC_SCRIPT_HAVE_TICTOC_CHANNELS) || \
    defined(UBASIC_SCRIPT_HAVE_SLEEP) ||           \
    defined(UBASIC_SCRIPT_HAVE_INPUT_FROM_SERIAL))
    data->mstimer_now = mstimer_now_u32;
#endif
#if defined(UBASIC_SCRIPT_HAVE_STORE_VARS_IN_FLASH)
    data->variable_write = variable_write;
    data->variable_read = variable_read;
#endif
#if defined(UBASIC_SCRIPT_HAVE_HARDWARE_EVENTS)
    data->hw_event = hw_event;
    data->hw_event_clear = hw_event_clear;
#endif
#if defined(UBASIC_SCRIPT_HAVE_PWM_CHANNELS)
    data->pwm_config = pwm_config;
    data->pwm_write = pwm_write;
    data->pwm_read = pwm_read;
#endif
#if defined(UBASIC_SCRIPT_HAVE_ANALOG_READ)
    data->adc_config = adc_config;
    data->adc_read = adc_read;
#endif
#if defined(UBASIC_SCRIPT_HAVE_GPIO_CHANNELS)
    data->gpio_config = gpio_config;
    data->gpio_write = gpio_write;
    data->gpio_read = gpio_read;
#endif
#if defined(UBASIC_SCRIPT_HAVE_RANDOM_NUMBER_GENERATOR)
    data->random_uint32 = random_uint32;
#endif
#if defined(UBASIC_SCRIPT_HAVE_PRINT_TO_SERIAL)
    data->serial_write = serial_write;
#endif
#if defined(UBASIC_SCRIPT_HAVE_INPUT_FROM_SERIAL)
    data->ubasic_getc = serial_getc;
#endif
#if defined(UBASIC_SCRIPT_HAVE_BACNET)
    data->bacnet_create_object = bacnet_create_object;
    data->bacnet_write_property = bacnet_write_property;
    data->bacnet_read_property = bacnet_read_property;
#endif
}

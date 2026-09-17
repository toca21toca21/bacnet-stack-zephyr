/**
 * @file
 * @brief uBASIC-Plus program object for BACnet - Zephyr port
 * @date 2026
 * @copyright SPDX-License-Identifier: MIT
 *
 * Originally ported from bacnet-stack's ports/stm32f4xx/program-ubasic.c
 * reference implementation (no changes needed there - it was already fully
 * portable, no STM32-specific code). Fixed one inconsistency present in the
 * reference: Program_UBASIC_Create() is declared void in the header but the
 * reference .c there returned int - this port matches the header (void).
 *
 * Since diverged from the reference for real network-writable scripts: the
 * reference only ever ran compiled-in, unchanging demo scripts, so
 * Program_Load()/Program_Restart() always replaying `context->program`
 * (a fixed pointer set once at creation) was never a problem there. Here,
 * the linked File object is genuinely writable over BACnet (AtomicWriteFile,
 * bacfile_ramfs-backed - see main.c), so Load/Restart need to pick up
 * whatever was most recently written, not a stale creation-time snapshot.
 * `bacfile_ramfs_file_data()` returns a pointer directly into ramfs's own
 * storage, but that storage can be realloc()'d (moved) by a WriteProperty
 * that arrives *while the script is running*, since everything here shares
 * one cooperative thread - holding onto that pointer across ticks would be
 * a use-after-free waiting to happen. So each Program instance gets its own
 * fixed-size scratch buffer (CONFIG_BACNETSTACK_UBASIC_SCRIPT_BUFFER_SIZE),
 * and Load/Restart copy the File's *current* content into it once, up
 * front, before handing it to the interpreter - safe regardless of what a
 * client writes afterward, until the next Load/Restart.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "bacnet/basic/object/program.h"
#include "bacnet/basic/program/ubasic/ubasic.h"
#include "bacnet/basic/sys/mstimer.h"
#include "bacnet/basic/sys/bramfs.h"

/* timer for the task */
static struct mstimer UBASIC_Timer;

/**
 * @brief Binds one uBASIC interpreter context to the File object pathname
 *  that holds its live source, plus a private scratch buffer Load/Restart
 *  copy that File's current content into (see file header comment for why
 *  a copy, not a live pointer into ramfs's own storage).
 */
#ifndef UBASIC_MAX_INSTANCES
#define UBASIC_MAX_INSTANCES 8
#endif
struct ubasic_file_binding {
    const struct ubasic_data *context;
    const char *pathname;
    const char *fallback_program;
    char buffer[CONFIG_BACNETSTACK_UBASIC_SCRIPT_BUFFER_SIZE];
};
static struct ubasic_file_binding Bindings[UBASIC_MAX_INSTANCES];
static size_t Binding_Count;

/**
 * @brief Find the file binding for a given interpreter context
 * @param context Pointer to the uBASIC data structure
 * @return matching binding, or NULL if this context was never bound (e.g.
 *  Program_UBASIC_Create() wasn't used to create it)
 */
static struct ubasic_file_binding *find_binding(const struct ubasic_data *context)
{
    size_t i;

    for (i = 0; i < Binding_Count; i++) {
        if (Bindings[i].context == context) {
            return &Bindings[i];
        }
    }

    return NULL;
}

/**
 * @brief Point context->program at the linked File object's *current*
 *  content, copied into this binding's private scratch buffer - falls back
 *  to the bootstrap script text if the File is empty (e.g. first boot,
 *  before any client has written to it) or its content doesn't fit the
 *  scratch buffer.
 * @param context Pointer to the uBASIC data structure
 */
static void ubasic_reload_from_file(struct ubasic_data *context)
{
    struct ubasic_file_binding *binding = find_binding(context);
    const char *file_data;
    size_t file_size;

    if (!binding) {
        /* not created via Program_UBASIC_Create() - leave as-is */
        return;
    }
    file_size = bacfile_ramfs_file_size(binding->pathname);
    if ((file_size == 0) || (file_size >= sizeof(binding->buffer))) {
        context->program = binding->fallback_program;
        return;
    }
    file_data = bacfile_ramfs_file_data(binding->pathname);
    if (!file_data) {
        context->program = binding->fallback_program;
        return;
    }
    memcpy(binding->buffer, file_data, file_size);
    binding->buffer[file_size] = '\0';
    context->program = binding->buffer;
}

/**
 * @brief Load the program into the uBASIC interpreter
 * @param context Pointer to the uBASIC data structure
 * @return 0 on success
 */
static int Program_Load(void *context)
{
    if (!context) {
        return -1;
    }
    struct ubasic_data *data = (struct ubasic_data *)context;

    ubasic_reload_from_file(data);
    ubasic_load_program(data, NULL);
    (void)ubasic_program_location(data);

    return 0;
}

/**
 * @brief Run the program in the uBASIC interpreter
 * @param context Pointer to the uBASIC data structure
 * @return 0 while the program is running, non-zero when finished
 *         or an error occurred
 */
static int Program_Run(void *context)
{
    if (!context) {
        return -1;
    }
    struct ubasic_data *data = (struct ubasic_data *)context;
    int result = 0;

    result = ubasic_run_program(data);
    if (result <= 0) {
        return -1;
    }
    (void)ubasic_program_location(data);

    return 0;
}

/**
 * @brief Halt the program in the uBASIC interpreter
 * @param context Pointer to the uBASIC data structure
 * @return 0 on success, non-zero on error
 */
static int Program_Halt(void *context)
{
    if (!context) {
        return -1;
    }
    struct ubasic_data *data = (struct ubasic_data *)context;

    ubasic_halt_program(data);

    return 0;
}

/**
 * @brief Restart the program in the uBASIC interpreter - re-reads the
 *  linked File object's current content, so "write a new script, then
 *  write RESTART to Program_Change" is a real remote-deploy workflow
 * @param context Pointer to the uBASIC data structure
 * @return 0 on success, non-zero on error
 */
static int Program_Restart(void *context)
{
    if (!context) {
        return -1;
    }
    struct ubasic_data *data = (struct ubasic_data *)context;

    ubasic_clear_variables(data);
    ubasic_reload_from_file(data);
    ubasic_load_program(data, NULL);
    (void)ubasic_program_location(data);

    return 0;
}

/**
 * @brief Unload the program in the uBASIC interpreter
 * @param context Pointer to the uBASIC data structure
 * @return 0 on success, non-zero on error
 */
static int Program_Unload(void *context)
{
    if (!context) {
        return -1;
    }
    struct ubasic_data *data = (struct ubasic_data *)context;

    ubasic_clear_variables(data);

    return 0;
}

/**
 * @brief Timer task for the uBASIC program object - drives Program_Timer()
 *  at a finer-grained cadence than the generic ~100ms object housekeeping
 *  tick, since scripts using sleep()/tic()/toc() want closer to real-time
 *  polling than that.
 */
void Program_UBASIC_Task(void)
{
    size_t index, max_index;
    uint32_t instance;

    if (mstimer_expired(&UBASIC_Timer)) {
        mstimer_reset(&UBASIC_Timer);
        max_index = Program_Count();
        for (index = 0; index < max_index; index++) {
            instance = Program_Index_To_Instance(index);
            Program_Timer(instance, mstimer_interval(&UBASIC_Timer));
        }
    }
}

/**
 * @brief Create one uBASIC program object, linked to a File object that
 *  holds its live, network-writable source (see program-ubasic.h for full
 *  parameter docs)
 */
void Program_UBASIC_Create(
    uint32_t requested_instance,
    struct ubasic_data *context,
    const char *program,
    const char *pathname)
{
    uint32_t instance = 0;
    struct ubasic_file_binding *binding;

    if (!context) {
        return;
    }
    if (Program_Valid_Instance(requested_instance)) {
        instance = requested_instance;
        if (program) {
            context->program = program;
        }
        Program_Change_Set(instance, PROGRAM_REQUEST_RESTART);
    } else {
        instance = Program_Create(requested_instance);
        if (instance == BACNET_MAX_INSTANCE) {
            return;
        }
        if (program) {
            context->program = program;
        } else {
            context->program = "end;";
        }
        if (Binding_Count < UBASIC_MAX_INSTANCES) {
            binding = &Bindings[Binding_Count++];
            binding->context = context;
            binding->pathname = pathname;
            binding->fallback_program = context->program;
            /* Seed the File object with the bootstrap text so an immediate
             * AtomicReadFile/RP reflects the actual running script instead
             * of an empty file, and so the first Load/Restart's
             * ubasic_reload_from_file() finds real content instead of
             * falling back - but ONLY if it's still empty. A caller may
             * have already restored persisted content into ramfs before
             * calling this function (see bacnet_ip_node_ubasic/main.c) -
             * unconditionally overwriting that with the compiled-in
             * default here would silently discard it every single boot. */
            if (pathname && (bacfile_ramfs_file_size(pathname) == 0)) {
                (void)bacfile_ramfs_write_stream_data(
                    pathname, 0, (const uint8_t *)context->program,
                    strlen(context->program));
            }
        }
        Program_Context_Set(instance, context);
        Program_Load_Set(instance, Program_Load);
        Program_Run_Set(instance, Program_Run);
        Program_Halt_Set(instance, Program_Halt);
        Program_Restart_Set(instance, Program_Restart);
        Program_Unload_Set(instance, Program_Unload);
        Program_Location_Set(instance, context->location);
        if (pathname) {
            Program_Instance_Of_Set(instance, pathname);
        }
        ubasic_port_init(context);
        /* auto-run the program */
        Program_Change_Set(instance, PROGRAM_REQUEST_RUN);
    }
}

/**
 * @brief Initialize the uBASIC program object subsystem
 * @param task_ms Cyclic run-timer interval, in milliseconds
 */
void Program_UBASIC_Init(unsigned long task_ms)
{
    /* start the cyclic run timer for the program object task */
    mstimer_set(&UBASIC_Timer, task_ms);
}

/**
 * @file
 * @brief Hardware-facing exports from ubasic-port.c - separate from
 *  program-ubasic.h on purpose, which is Program-object lifecycle only.
 * @date 2026
 * @copyright SPDX-License-Identifier: MIT
 */
#ifndef UBASIC_PORT_H
#define UBASIC_PORT_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Set a hardware event bit, readable from a running uBASIC script
 *  via flag(bit) - see ubasic-port.c's own comment on
 *  ubasic_port_hw_event_set() for why this is safe to call from ordinary
 *  application code with no locking (single cooperative thread, no ISR
 *  involved).
 * @param bit Event bit (0-31)
 */
void ubasic_port_hw_event_set(uint8_t bit);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif

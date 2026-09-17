/**
 * @file
 * @brief uBASIC-Plus program object for BACnet - Zephyr port
 * @date 2026
 * @copyright SPDX-License-Identifier: MIT
 *
 * Originally ported from bacnet-stack's ports/stm32f4xx/program-ubasic.{c,h}
 * reference implementation (which needed no changes - it was already fully
 * portable, no STM32-specific code). Since diverged: Program_UBASIC_Create()
 * gained a `pathname` parameter so Load/Restart can re-read the linked File
 * object's *current* content instead of always replaying the fixed
 * `program` pointer given at creation - see the .c file for the reasoning.
 */
#ifndef PROGRAM_UBASIC_H
#define PROGRAM_UBASIC_H
#include <stdint.h>
#include <stdbool.h>
#include "bacnet/basic/program/ubasic/ubasic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void Program_UBASIC_Task(void);
/**
 * @brief Create one uBASIC Program object, linked to a File object that
 *  holds its live, network-writable source.
 * @param instance Program (and File) object instance number
 * @param data uBASIC interpreter context - must remain valid for the life
 *  of the object (typically a static/file-scope struct)
 * @param program Fallback/bootstrap script text, used whenever the linked
 *  File object is empty (e.g. this device's first boot, before any client
 *  has written a script) - typically a string literal
 * @param pathname The linked File object's pathname (also used as the key
 *  into the ramfs content store, and recorded in Program_Instance_Of so a
 *  BACnet client can discover which File object to write a new script to)
 */
void Program_UBASIC_Create(
    uint32_t instance,
    struct ubasic_data *data,
    const char *program,
    const char *pathname);
void Program_UBASIC_Init(unsigned long task_ms);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif

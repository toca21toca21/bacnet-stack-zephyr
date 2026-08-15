/**
 * @file
 * @brief Zephyr port of the BACnet/SC global websocket dispatch lock.
 * @copyright SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
/* BACnet Stack defines - first */
#include "bacnet/bacdef.h"
/* BACnet Stack API */
#include "bacnet/datalink/bsc/websocket.h"

/* Single global recursive lock serializing all dispatch_func() callback
 * invocations across every BSC websocket client/server instance - same
 * role as websocket_dispatch_mutex in ports/linux and ports/bsd.
 */
K_MUTEX_DEFINE(bws_dispatch_mutex);

void bws_dispatch_lock(void)
{
    k_mutex_lock(&bws_dispatch_mutex, K_FOREVER);
}

void bws_dispatch_unlock(void)
{
    k_mutex_unlock(&bws_dispatch_mutex);
}
/**
 * @file
 * @brief Zephyr port of the BACnet/SC cross-platform event abstraction.
 * @copyright SPDX-License-Identifier: MIT
 */
#include <stdbool.h>
#include <stddef.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
/* BACnet Stack defines - first */
#include "bacnet/bacdef.h"
/* BACnet Stack API */
#include "bacnet/datalink/bsc/bsc-event.h"

/* Mirrors ports/linux and ports/bsd: bsc_event_signal() must wake every
 * thread currently blocked in bsc_event_wait()/bsc_event_timedwait(), and
 * the event only resets once the last of them has left. Zephyr's k_sem
 * only releases one waiter per k_sem_give(), so this needs a mutex +
 * condvar + waiter count instead, same as the pthread reference.
 */
struct BSC_Event {
    struct k_mutex mutex;
    struct k_condvar cond;
    bool signalled;
    size_t waiters;
};

BSC_EVENT *bsc_event_init(void)
{
    struct BSC_Event *ev = k_malloc(sizeof(struct BSC_Event));

    if (!ev) {
        return NULL;
    }
    k_mutex_init(&ev->mutex);
    k_condvar_init(&ev->cond);
    ev->signalled = false;
    ev->waiters = 0;
    return ev;
}

void bsc_event_deinit(BSC_EVENT *ev)
{
    if (ev) {
        k_free(ev);
    }
}

void bsc_wait(int seconds)
{
    k_sleep(K_SECONDS(seconds));
}

void bsc_wait_ms(int mseconds)
{
    k_sleep(K_MSEC(mseconds));
}

void bsc_event_wait(BSC_EVENT *ev)
{
    if (!ev) {
        return;
    }
    k_mutex_lock(&ev->mutex, K_FOREVER);
    ev->waiters++;
    while (!ev->signalled) {
        k_condvar_wait(&ev->cond, &ev->mutex, K_FOREVER);
    }
    ev->waiters--;
    if (ev->waiters == 0) {
        ev->signalled = false;
    } else {
        /* other waiters still need to observe the signalled state
         * before it resets - keep waking them */
        k_condvar_broadcast(&ev->cond);
    }
    k_mutex_unlock(&ev->mutex);
}

bool bsc_event_timedwait(BSC_EVENT *ev, unsigned int ms_timeout)
{
    int rc = 0;

    if (!ev) {
        return false;
    }
    k_mutex_lock(&ev->mutex, K_FOREVER);
    ev->waiters++;
    while (!ev->signalled && rc == 0) {
        rc = k_condvar_wait(&ev->cond, &ev->mutex, K_MSEC(ms_timeout));
    }
    /* signalled winning the race counts as success even if the last
     * k_condvar_wait() call itself returned -EAGAIN */
    if (ev->signalled) {
        rc = 0;
    }
    ev->waiters--;
    if (ev->waiters == 0) {
        ev->signalled = false;
    } else {
        k_condvar_broadcast(&ev->cond);
    }
    k_mutex_unlock(&ev->mutex);
    return rc == 0;
}

void bsc_event_signal(BSC_EVENT *ev)
{
    if (!ev) {
        return;
    }
    k_mutex_lock(&ev->mutex, K_FOREVER);
    ev->signalled = true;
    k_condvar_broadcast(&ev->cond);
    k_mutex_unlock(&ev->mutex);
}

void bsc_generate_random_vmac(BACNET_SC_VMAC_ADDRESS *p)
{
    if (!p) {
        return;
    }
    sys_rand_get(p->address, sizeof(p->address));
    /* AB.7.3 EUI-48 and Random-48 VMAC Address: least significant 4 bits
     * of the first octet must be b'0010' (0x2); remaining bits random */
    p->address[0] = (p->address[0] & 0xF0) | 0x02;
}

void bsc_generate_random_uuid(BACNET_SC_UUID *p)
{
    if (!p) {
        return;
    }
    sys_rand_get(p->uuid, sizeof(p->uuid));
    /* RFC 4122 version 4 (random) + variant bits, per the UUID
     * requirement in AB.1.5.3 Device UUID */
    p->uuid[6] = (p->uuid[6] & 0x0F) | 0x40;
    p->uuid[8] = (p->uuid[8] & 0x3F) | 0x80;
}
/**
 * @file
 * @brief Zephyr port of the BACnet/SC websocket client interface.
 *
 * Implements bws_cli_connect()/disconnect()/send()/dispatch_send() (see
 * bacnet/datalink/bsc/websocket.h) on top of Zephyr's own native
 * websocket client (CONFIG_WEBSOCKET_CLIENT, zephyr/net/websocket.h) and
 * TLS sockets (CONFIG_NET_SOCKETS_SOCKOPT_TLS). Zephyr's websocket_connect()
 * only performs the HTTP Upgrade handshake over an already-connected,
 * already TLS-wrapped socket - opening that socket and doing the TLS
 * handshake is this file's job.
 *
 * One Zephyr thread services each open connection (connect + HTTP
 * upgrade + subsequent send/receive polling), matching the "1 thread per
 * client instance" model the BSC README describes for the libwebsockets
 * based ports (bsd/linux/win32). Unlike those ports there is no
 * event-driven "socket became writable" callback available here, so the
 * service loop polls on a short timeout and checks the want-to-send flag
 * each iteration - see BSC_CLI_POLL_TIMEOUT_MS below.
 *
 * NOTE: this file is new and has not been built or run - it was written
 * by reading the Zephyr websocket/tls_credentials headers and the
 * bacnet-stack ports/bsd/websocket-cli.c reference implementation, not
 * verified on hardware. Expect to debug it.
 *
 * @copyright SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/websocket.h>
/* BACnet Stack defines - first */
#include "bacnet/bacdef.h"
#include "bacnet/bacenum.h"
/* BACnet Stack API */
#include "bacnet/datalink/bsc/websocket.h"
#include "bacnet/datalink/bsc/bsc-conf.h"

/* Logging module registration is already done in ports/zephyr/main.c */
#include "bacnet_osif/bacnet_log.h"
LOG_MODULE_DECLARE(bacnet, CONFIG_BACNETSTACK_LOG_LEVEL);

#define THIS_FILE "websocket-cli.c"

/* How often the per-connection service thread wakes up (absent any
 * socket activity) to check for a pending disconnect or send request.
 * Bounds worst-case send/disconnect latency; lower it if that latency
 * matters more than the extra wakeups, this is a starting point.
 */
#define BSC_CLI_POLL_TIMEOUT_MS 200

/* Base TLS secure tag; each connection slot gets BSC_CLI_TLS_SEC_TAG_BASE
 * + slot index so concurrent connections (primary/failover hub, direct
 * connections) don't clobber each other's credentials.
 */
#define BSC_CLI_TLS_SEC_TAG_BASE 100

/* This one thread does zsock_poll + TLS record recv/send (mbedTLS ECDSA/
 * AES-GCM operations included) + BVLC-SC and BACnet APDU decode/encode +
 * verbose DEBUG_PRINTF tracing, all in a single nested call chain - 6144
 * was an untested starting guess, bumped after a crash whose signature
 * (bus fault on vector table read, LR pointing into RAM, PC near 0, no
 * specific trigger) matched an undetected stack overflow. Pair with
 * CONFIG_HW_STACK_PROTECTION in prj.conf so any future overflow faults
 * immediately instead of silently corrupting adjacent memory. */
#define BSC_CLI_THREAD_STACK_SIZE 8192
#define BSC_CLI_THREAD_PRIORITY 5

typedef enum {
    BSC_WEBSOCKET_STATE_IDLE = 0,
    BSC_WEBSOCKET_STATE_CONNECTING = 1,
    BSC_WEBSOCKET_STATE_CONNECTED = 2,
    BSC_WEBSOCKET_STATE_DISCONNECTING = 3
} BSC_WEBSOCKET_STATE;

typedef struct {
    BSC_WEBSOCKET_STATE state;
    BSC_WEBSOCKET_PROTOCOL proto;
    int tcp_sock;
    int ws_sock;
    bool want_send_data;
    bool can_send_data;
    bool stop_requested;
    BSC_WEBSOCKET_CLI_DISPATCH dispatch_func;
    void *user_param;
    char url[BSC_WSURL_MAX_LEN];
    size_t timeout_s;
    /* certs/key are only needed transiently during connect - copied into
     * a per-slot buffer since bws_cli_connect() cannot assume the
     * caller's pointers stay valid after it returns (bsc_node_conf_cleanup()
     * may free them once bsc_node_init() has consumed them) */
    uint8_t ca_cert[2048];
    size_t ca_cert_size;
    uint8_t cert[2048];
    size_t cert_size;
    uint8_t key[2048];
    size_t key_size;
    uint8_t rx_buf[BSC_WEBSOCKET_RX_BUFFER_LEN];
    char err_desc[BSC_WEBSOCKET_ERR_DESC_STR_MAX_LEN];
    BACNET_ERROR_CODE err_code;
    struct k_thread thread;
} BSC_WEBSOCKET_CONNECTION;

/* Global lock protecting the connection table below - distinct from
 * bws_dispatch_lock()/unlock() (websocket-global.c), which only
 * serializes dispatch_func() invocations against each other.
 */
K_MUTEX_DEFINE(bws_cli_mutex);

static BSC_WEBSOCKET_CONNECTION bws_cli_conn[BSC_CLIENT_WEBSOCKETS_MAX_NUM];

K_THREAD_STACK_ARRAY_DEFINE(
    bws_cli_stacks, BSC_CLIENT_WEBSOCKETS_MAX_NUM, BSC_CLI_THREAD_STACK_SIZE);

static BSC_WEBSOCKET_HANDLE bws_cli_alloc_connection(void)
{
    int i;

    for (i = 0; i < BSC_CLIENT_WEBSOCKETS_MAX_NUM; i++) {
        if (bws_cli_conn[i].state == BSC_WEBSOCKET_STATE_IDLE) {
            memset(&bws_cli_conn[i], 0, sizeof(bws_cli_conn[i]));
            bws_cli_conn[i].tcp_sock = -1;
            bws_cli_conn[i].ws_sock = -1;
            return i;
        }
    }
    return BSC_WEBSOCKET_INVALID_HANDLE;
}

/**
 * @brief Parse a "wss://host[:port][/path]" URL.
 * @return true if the URL was a well-formed wss:// URL
 */
static bool bsc_parse_wss_url(
    const char *url,
    char *host_out,
    size_t host_out_len,
    uint16_t *port_out,
    char *path_out,
    size_t path_out_len)
{
    const char *p;
    const char *host_start;
    const char *host_end;
    const char *port_start = NULL;
    size_t host_len;

    if (!url || !host_out || !port_out || !path_out) {
        return false;
    }
    if (strncmp(url, "wss://", 6) != 0) {
        return false;
    }
    host_start = url + 6;
    p = host_start;
    while (*p && *p != '/' && *p != ':') {
        p++;
    }
    host_end = p;
    host_len = (size_t)(host_end - host_start);
    if (host_len == 0 || host_len >= host_out_len) {
        return false;
    }
    memcpy(host_out, host_start, host_len);
    host_out[host_len] = 0;

    *port_out = 443;
    if (*p == ':') {
        port_start = ++p;
        while (*p && *p != '/') {
            p++;
        }
        if (p == port_start) {
            return false;
        }
        *port_out = (uint16_t)strtoul(port_start, NULL, 10);
    }

    if (*p == '/') {
        if (strlen(p) >= path_out_len) {
            return false;
        }
        strcpy(path_out, p);
    } else {
        if (path_out_len < 2) {
            return false;
        }
        strcpy(path_out, "/");
    }
    return true;
}

static void bsc_cli_report_err(
    BSC_WEBSOCKET_CONNECTION *conn, BACNET_ERROR_CODE code, const char *desc)
{
    if (conn->err_code == ERROR_CODE_SUCCESS) {
        conn->err_code = code;
        if (desc) {
            strncpy(conn->err_desc, desc, sizeof(conn->err_desc) - 1);
            conn->err_desc[sizeof(conn->err_desc) - 1] = 0;
        } else {
            conn->err_desc[0] = 0;
        }
    }
}

static void bsc_cli_close_sockets(BSC_WEBSOCKET_CONNECTION *conn)
{
    if (conn->ws_sock >= 0) {
        /* websocket_disconnect() only closes the websocket-layer fd - per
         * its own header doc, the underlying "real" socket passed into
         * websocket_connect() is a separate fd that the websocket layer
         * never closes on its own (see websocket_unregister(), which
         * exists specifically to close both together). Leaving tcp_sock
         * open here leaked one Zephyr TLS context per connection torn
         * down - with CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS this small,
         * that exhausted the pool ("Failed to allocate TLS context")
         * within a few reconnect cycles after a hub restart. */
        websocket_disconnect(conn->ws_sock);
        conn->ws_sock = -1;
    }
    if (conn->tcp_sock >= 0) {
        zsock_close(conn->tcp_sock);
        conn->tcp_sock = -1;
    }
}

/**
 * @brief Receive and dispatch one complete websocket message, if any is
 * available within the given poll timeout.
 * @return false if the connection should be torn down
 */
static bool bsc_cli_service_recv(BSC_WEBSOCKET_CONNECTION *conn, int handle)
{
    uint32_t message_type = 0;
    uint64_t remaining = 0;
    size_t total = 0;
    int rc;
    BSC_WEBSOCKET_CLI_DISPATCH dispatch_func;
    void *user_param;

    do {
        rc = websocket_recv_msg(
            conn->ws_sock, &conn->rx_buf[total],
            sizeof(conn->rx_buf) - total, &message_type, &remaining, 0);
        if (rc == -EAGAIN) {
            /* nothing more ready right now */
            return true;
        }
        if (rc < 0) {
            LOG_WRN(
                "%s:%d - websocket_recv_msg() error %d", THIS_FILE, __LINE__,
                rc);
            bsc_cli_report_err(conn, ERROR_CODE_WEBSOCKET_ERROR, NULL);
            return false;
        }
        total += (size_t)rc;
        if (message_type & WEBSOCKET_FLAG_CLOSE) {
            LOG_INF("%s:%d - peer closed websocket", THIS_FILE, __LINE__);
            bsc_cli_report_err(
                conn, ERROR_CODE_WEBSOCKET_CLOSED_BY_PEER, NULL);
            return false;
        }
        if (total >= sizeof(conn->rx_buf) && remaining > 0) {
            LOG_WRN(
                "%s:%d - message exceeds RX buffer (%u), dropped", THIS_FILE,
                __LINE__, (unsigned)sizeof(conn->rx_buf));
            bsc_cli_report_err(conn, ERROR_CODE_WEBSOCKET_FRAME_TOO_LONG, NULL);
            return false;
        }
    } while (remaining > 0);

    if (!(message_type & WEBSOCKET_FLAG_BINARY)) {
        /* AB.7.5.3 BACnet/SC BVLC Message Exchange: a non-binary data
         * frame must cause the connection to be closed. */
        LOG_WRN("%s:%d - non-binary frame received, closing", THIS_FILE,
            __LINE__);
        bsc_cli_report_err(conn, ERROR_CODE_WEBSOCKET_DATA_NOT_ACCEPTED, NULL);
        return false;
    }

    dispatch_func = conn->dispatch_func;
    user_param = conn->user_param;
    k_mutex_unlock(&bws_cli_mutex);
    bws_dispatch_lock();
    dispatch_func(
        handle, BSC_WEBSOCKET_RECEIVED, 0, NULL, conn->rx_buf, total,
        user_param);
    bws_dispatch_unlock();
    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    return true;
}

static void bws_cli_thread_entry(void *p1, void *p2, void *p3)
{
    BSC_WEBSOCKET_CONNECTION *conn = (BSC_WEBSOCKET_CONNECTION *)p1;
    int handle = (int)(intptr_t)p2;
    ARG_UNUSED(p3);
    char host[64];
    char path[BSC_WSURL_MAX_LEN];
    uint16_t port;
    struct zsock_addrinfo hints = { 0 };
    struct zsock_addrinfo *res = NULL;
    int rc;
    sec_tag_t sec_tag = BSC_CLI_TLS_SEC_TAG_BASE + handle;
    sec_tag_t sec_tag_list[1] = { sec_tag };
    struct websocket_request req = { 0 };
    static uint8_t tmp_buf[BSC_CLIENT_WEBSOCKETS_MAX_NUM][512];
    char host_hdr[80];
    const char *hub_hdr = "Sec-WebSocket-Protocol: " BSC_WEBSOCKET_HUB_PROTOCOL_STR "\r\n";
    const char *direct_hdr =
        "Sec-WebSocket-Protocol: " BSC_WEBSOCKET_DIRECT_PROTOCOL_STR "\r\n";
    const char *opt_headers[2];
    BSC_WEBSOCKET_CLI_DISPATCH dispatch_func;
    void *user_param;
    BACNET_ERROR_CODE err_code;
    char err_desc[BSC_WEBSOCKET_ERR_DESC_STR_MAX_LEN];

    k_mutex_lock(&bws_cli_mutex, K_FOREVER);

    if (!bsc_parse_wss_url(
            conn->url, host, sizeof(host), &port, path, sizeof(path))) {
        bsc_cli_report_err(conn, ERROR_CODE_WEBSOCKET_ERROR, "bad url");
        goto fail_no_socket;
    }

    tls_credential_delete(sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PRIVATE_KEY);

    rc = tls_credential_add(
        sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE, conn->ca_cert,
        conn->ca_cert_size);
    if (rc < 0) {
        LOG_ERR(
            "%s:%d - tls_credential_add(CA) failed: %d", THIS_FILE, __LINE__,
            rc);
        bsc_cli_report_err(conn, ERROR_CODE_TLS_ERROR, "ca cert");
        goto fail_no_socket;
    }
    rc = tls_credential_add(
        sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE, conn->cert,
        conn->cert_size);
    if (rc < 0) {
        LOG_ERR(
            "%s:%d - tls_credential_add(cert) failed: %d", THIS_FILE, __LINE__,
            rc);
        bsc_cli_report_err(conn, ERROR_CODE_TLS_ERROR, "client cert");
        goto fail_no_socket;
    }
    rc = tls_credential_add(
        sec_tag, TLS_CREDENTIAL_PRIVATE_KEY, conn->key, conn->key_size);
    if (rc < 0) {
        LOG_ERR(
            "%s:%d - tls_credential_add(key) failed: %d", THIS_FILE, __LINE__,
            rc);
        bsc_cli_report_err(conn, ERROR_CODE_TLS_ERROR, "client key");
        goto fail_no_socket;
    }

    k_mutex_unlock(&bws_cli_mutex);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    {
        char port_str[6];

        snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
        rc = zsock_getaddrinfo(host, port_str, &hints, &res);
    }
    if (rc != 0 || !res) {
        LOG_ERR(
            "%s:%d - DNS resolution of %s failed: %d", THIS_FILE, __LINE__,
            host, rc);
        k_mutex_lock(&bws_cli_mutex, K_FOREVER);
        bsc_cli_report_err(conn, ERROR_CODE_WEBSOCKET_ERROR, "dns failure");
        goto fail_no_socket;
    }

    conn->tcp_sock =
        zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (conn->tcp_sock < 0) {
        LOG_ERR("%s:%d - socket() failed: %d", THIS_FILE, __LINE__, errno);
        zsock_freeaddrinfo(res);
        k_mutex_lock(&bws_cli_mutex, K_FOREVER);
        bsc_cli_report_err(conn, ERROR_CODE_TLS_ERROR, "socket");
        goto fail_no_socket;
    }

    rc = zsock_setsockopt(
        conn->tcp_sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list,
        sizeof(sec_tag_list));
    if (rc != 0) {
        LOG_ERR(
            "%s:%d - setsockopt(TLS_SEC_TAG_LIST) failed: %d", THIS_FILE,
            __LINE__, errno);
    }
    if (rc == 0) {
        rc = zsock_setsockopt(
            conn->tcp_sock, SOL_TLS, TLS_HOSTNAME, host, strlen(host) + 1);
        if (rc != 0) {
            LOG_ERR(
                "%s:%d - setsockopt(TLS_HOSTNAME, %s) failed: %d", THIS_FILE,
                __LINE__, host, errno);
        }
    }
    if (rc == 0) {
        /* TEST/INSECURE MODE: the certs currently in bsc_certs.c are test
         * certificates not issued for this hub's real domain, so peer
         * (hub) certificate verification would fail regardless of
         * whether the handshake itself works. TLS_PEER_VERIFY_NONE only
         * disables *our* verification of the hub's certificate - we still
         * present our own client cert/key (registered above), since BSC
         * requires mutual auth on the wire regardless of this setting.
         * Revert to TLS_PEER_VERIFY_REQUIRED once real, domain-matched
         * certs are in place. */
        int peer_verify = TLS_PEER_VERIFY_NONE;

        rc = zsock_setsockopt(
            conn->tcp_sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify,
            sizeof(peer_verify));
        if (rc != 0) {
            LOG_ERR(
                "%s:%d - setsockopt(TLS_PEER_VERIFY) failed: %d", THIS_FILE,
                __LINE__, errno);
        }
    }
    if (rc == 0) {
        struct zsock_timeval tv = { .tv_sec = (long)conn->timeout_s, .tv_usec = 0 };

        zsock_setsockopt(
            conn->tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        zsock_setsockopt(
            conn->tcp_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    if (rc != 0) {
        zsock_freeaddrinfo(res);
        k_mutex_lock(&bws_cli_mutex, K_FOREVER);
        bsc_cli_report_err(conn, ERROR_CODE_TLS_ERROR, "tls setup");
        goto fail_close_socket;
    }

    rc = zsock_connect(conn->tcp_sock, res->ai_addr, res->ai_addrlen);
    zsock_freeaddrinfo(res);
    if (rc != 0) {
        LOG_ERR(
            "%s:%d - TLS connect() to %s:%u failed: %d", THIS_FILE, __LINE__,
            host, (unsigned)port, errno);
        k_mutex_lock(&bws_cli_mutex, K_FOREVER);
        bsc_cli_report_err(conn, ERROR_CODE_TLS_ERROR, "tls connect");
        goto fail_close_socket;
    }

    if (port == 443) {
        snprintf(host_hdr, sizeof(host_hdr), "%s", host);
    } else {
        snprintf(host_hdr, sizeof(host_hdr), "%s:%u", host, (unsigned)port);
    }
    opt_headers[0] =
        (conn->proto == BSC_WEBSOCKET_HUB_PROTOCOL) ? hub_hdr : direct_hdr;
    opt_headers[1] = NULL;

    req.host = host_hdr;
    req.url = path;
    req.optional_headers = opt_headers;
    req.cb = NULL;
    req.tmp_buf = tmp_buf[handle];
    req.tmp_buf_len = sizeof(tmp_buf[handle]);

    rc = websocket_connect(
        conn->tcp_sock, &req, (int32_t)(conn->timeout_s * 1000), NULL);
    if (rc < 0) {
        LOG_ERR(
            "%s:%d - websocket_connect() failed: %d", THIS_FILE, __LINE__, rc);
        k_mutex_lock(&bws_cli_mutex, K_FOREVER);
        bsc_cli_report_err(
            conn, ERROR_CODE_WEBSOCKET_ERROR, "ws upgrade failed");
        goto fail_close_socket;
    }

    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    conn->ws_sock = rc;
    conn->state = BSC_WEBSOCKET_STATE_CONNECTED;
    dispatch_func = conn->dispatch_func;
    user_param = conn->user_param;
    k_mutex_unlock(&bws_cli_mutex);

    bws_dispatch_lock();
    dispatch_func(handle, BSC_WEBSOCKET_CONNECTED, 0, NULL, NULL, 0, user_param);
    bws_dispatch_unlock();

    k_mutex_lock(&bws_cli_mutex, K_FOREVER);

    /* service loop: poll for incoming data / a pending send request /
     * a disconnect request until one of those tears the connection down */
    while (!conn->stop_requested) {
        struct zsock_pollfd fds[1];
        bool wake_for_send = conn->want_send_data;

        fds[0].fd = conn->ws_sock;
        fds[0].events = ZSOCK_POLLIN | (wake_for_send ? ZSOCK_POLLOUT : 0);
        fds[0].revents = 0;
        k_mutex_unlock(&bws_cli_mutex);
        rc = zsock_poll(fds, 1, BSC_CLI_POLL_TIMEOUT_MS);
        k_mutex_lock(&bws_cli_mutex, K_FOREVER);

        if (conn->stop_requested) {
            break;
        }
        if (rc < 0) {
            LOG_WRN("%s:%d - poll() error: %d", THIS_FILE, __LINE__, errno);
            bsc_cli_report_err(conn, ERROR_CODE_WEBSOCKET_ERROR, "poll error");
            break;
        }
        if (rc == 0) {
            continue;
        }
        if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP | ZSOCK_POLLNVAL)) {
            bsc_cli_report_err(
                conn, ERROR_CODE_WEBSOCKET_CLOSED_BY_PEER, NULL);
            break;
        }
        if (fds[0].revents & ZSOCK_POLLIN) {
            if (!bsc_cli_service_recv(conn, handle)) {
                break;
            }
        }
        if ((fds[0].revents & ZSOCK_POLLOUT) && conn->want_send_data) {
            conn->can_send_data = true;
            dispatch_func = conn->dispatch_func;
            user_param = conn->user_param;
            k_mutex_unlock(&bws_cli_mutex);
            bws_dispatch_lock();
            dispatch_func(
                handle, BSC_WEBSOCKET_SENDABLE, 0, NULL, NULL, 0, user_param);
            bws_dispatch_unlock();
            k_mutex_lock(&bws_cli_mutex, K_FOREVER);
            conn->want_send_data = false;
            conn->can_send_data = false;
        }
    }

    dispatch_func = conn->dispatch_func;
    user_param = conn->user_param;
    err_code = conn->err_code;
    memcpy(err_desc, conn->err_desc, sizeof(err_desc));
    bsc_cli_close_sockets(conn);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PRIVATE_KEY);
    k_mutex_unlock(&bws_cli_mutex);

    bws_dispatch_lock();
    dispatch_func(
        handle, BSC_WEBSOCKET_DISCONNECTED, err_code,
        err_code != ERROR_CODE_SUCCESS ? err_desc : NULL, NULL, 0, user_param);
    bws_dispatch_unlock();

    /* Only now is it safe for this slot (and this thread's own stack) to
     * be handed to a new connection: the hub-connector's disconnect
     * handler above commonly triggers a reconnect *synchronously*, from
     * within this same call - if the slot were already marked IDLE
     * before dispatch_func() ran, that reentrant bws_cli_connect() could
     * pick this exact slot and k_thread_create() a new thread directly
     * on top of the stack this thread is still executing on. Bug found
     * via a reproducible crash (jump to 0xAAAAAAAA, Zephyr's stack-poison
     * fill pattern) when reconnecting right after the hub was stopped. */
    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    conn->state = BSC_WEBSOCKET_STATE_IDLE;
    k_mutex_unlock(&bws_cli_mutex);
    return;

fail_close_socket:
    bsc_cli_close_sockets(conn);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PRIVATE_KEY);
fail_no_socket:
    dispatch_func = conn->dispatch_func;
    user_param = conn->user_param;
    err_code = conn->err_code;
    memcpy(err_desc, conn->err_desc, sizeof(err_desc));
    k_mutex_unlock(&bws_cli_mutex);

    bws_dispatch_lock();
    dispatch_func(
        handle, BSC_WEBSOCKET_DISCONNECTED, err_code,
        err_code != ERROR_CODE_SUCCESS ? err_desc : NULL, NULL, 0, user_param);
    bws_dispatch_unlock();

    /* Same reentrancy hazard as the main exit path above - see the
     * comment there. */
    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    conn->state = BSC_WEBSOCKET_STATE_IDLE;
    k_mutex_unlock(&bws_cli_mutex);
}

BSC_WEBSOCKET_RET bws_cli_connect(
    BSC_WEBSOCKET_PROTOCOL proto,
    char *url,
    uint8_t *ca_cert,
    size_t ca_cert_size,
    uint8_t *cert,
    size_t cert_size,
    uint8_t *key,
    size_t key_size,
    size_t timeout_s,
    BSC_WEBSOCKET_CLI_DISPATCH dispatch_func,
    void *dispatch_func_user_param,
    BSC_WEBSOCKET_HANDLE *out_handle)
{
    BSC_WEBSOCKET_HANDLE h;
    BSC_WEBSOCKET_CONNECTION *conn;

    if (!ca_cert || !ca_cert_size || !cert || !cert_size || !key || !key_size ||
        !url || !out_handle || !timeout_s || !dispatch_func) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    if (proto != BSC_WEBSOCKET_HUB_PROTOCOL &&
        proto != BSC_WEBSOCKET_DIRECT_PROTOCOL) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    if (strncmp(url, "wss://", 6) != 0) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    if (strlen(url) >= sizeof(bws_cli_conn[0].url) ||
        ca_cert_size > sizeof(bws_cli_conn[0].ca_cert) ||
        cert_size > sizeof(bws_cli_conn[0].cert) ||
        key_size > sizeof(bws_cli_conn[0].key)) {
        LOG_ERR(
            "%s:%d - url or credential too large for fixed buffers",
            THIS_FILE, __LINE__);
        return BSC_WEBSOCKET_BAD_PARAM;
    }

    *out_handle = BSC_WEBSOCKET_INVALID_HANDLE;

    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    h = bws_cli_alloc_connection();
    if (h == BSC_WEBSOCKET_INVALID_HANDLE) {
        k_mutex_unlock(&bws_cli_mutex);
        return BSC_WEBSOCKET_NO_RESOURCES;
    }

    conn = &bws_cli_conn[h];
    conn->state = BSC_WEBSOCKET_STATE_CONNECTING;
    conn->proto = proto;
    strcpy(conn->url, url);
    conn->timeout_s = timeout_s;
    conn->dispatch_func = dispatch_func;
    conn->user_param = dispatch_func_user_param;
    memcpy(conn->ca_cert, ca_cert, ca_cert_size);
    conn->ca_cert_size = ca_cert_size;
    memcpy(conn->cert, cert, cert_size);
    conn->cert_size = cert_size;
    memcpy(conn->key, key, key_size);
    conn->key_size = key_size;
    conn->err_code = ERROR_CODE_SUCCESS;

    k_thread_create(
        &conn->thread, bws_cli_stacks[h],
        K_THREAD_STACK_SIZEOF(bws_cli_stacks[h]), bws_cli_thread_entry, conn,
        (void *)(intptr_t)h, NULL, BSC_CLI_THREAD_PRIORITY, 0, K_NO_WAIT);
    k_thread_name_set(&conn->thread, "bsc_cli");

    *out_handle = h;
    k_mutex_unlock(&bws_cli_mutex);
    return BSC_WEBSOCKET_SUCCESS;
}

void bws_cli_disconnect(BSC_WEBSOCKET_HANDLE h)
{
    if (h < 0 || h >= BSC_CLIENT_WEBSOCKETS_MAX_NUM) {
        return;
    }
    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    if (bws_cli_conn[h].state == BSC_WEBSOCKET_STATE_CONNECTING ||
        bws_cli_conn[h].state == BSC_WEBSOCKET_STATE_CONNECTED) {
        bws_cli_conn[h].stop_requested = true;
    }
    k_mutex_unlock(&bws_cli_mutex);
}

void bws_cli_send(BSC_WEBSOCKET_HANDLE h)
{
    if (h < 0 || h >= BSC_CLIENT_WEBSOCKETS_MAX_NUM) {
        return;
    }
    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    if (bws_cli_conn[h].state == BSC_WEBSOCKET_STATE_CONNECTED) {
        bws_cli_conn[h].want_send_data = true;
    }
    k_mutex_unlock(&bws_cli_mutex);
}

BSC_WEBSOCKET_RET bws_cli_dispatch_send(
    BSC_WEBSOCKET_HANDLE h, uint8_t *payload, size_t payload_size)
{
    BSC_WEBSOCKET_RET ret;
    int written;

    if (h < 0 || h >= BSC_CLIENT_WEBSOCKETS_MAX_NUM) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }

    k_mutex_lock(&bws_cli_mutex, K_FOREVER);
    if (bws_cli_conn[h].state != BSC_WEBSOCKET_STATE_CONNECTED ||
        !bws_cli_conn[h].want_send_data || !bws_cli_conn[h].can_send_data) {
        k_mutex_unlock(&bws_cli_mutex);
        return BSC_WEBSOCKET_INVALID_OPERATION;
    }

    /* client-originated frames must be masked per RFC 6455 5.1 */
    written = websocket_send_msg(
        bws_cli_conn[h].ws_sock, payload, payload_size,
        WEBSOCKET_OPCODE_DATA_BINARY, true, true,
        (int32_t)(bws_cli_conn[h].timeout_s * 1000));

    if (written < (int)payload_size) {
        LOG_WRN(
            "%s:%d - websocket_send_msg() short/failed write: %d", THIS_FILE,
            __LINE__, written);
        bws_cli_conn[h].stop_requested = true;
        ret = BSC_WEBSOCKET_INVALID_OPERATION;
    } else {
        ret = BSC_WEBSOCKET_SUCCESS;
    }
    k_mutex_unlock(&bws_cli_mutex);
    return ret;
}
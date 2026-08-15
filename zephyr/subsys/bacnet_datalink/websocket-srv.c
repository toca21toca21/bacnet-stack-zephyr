/**
 * @file
 * @brief Zephyr port of the BACnet/SC websocket SERVER interface -
 *  the hub function's accept side (bws_srv_*, see
 *  bacnet/datalink/bsc/websocket.h).
 *
 * Built on the same primitives as websocket-cli.c (Zephyr's native
 * CONFIG_WEBSOCKET_CLIENT + CONFIG_NET_SOCKETS_SOCKOPT_TLS), plus one
 * piece websocket-cli.c doesn't need: the server side of the RFC 6455
 * HTTP Upgrade handshake, done by hand here rather than via Zephyr's
 * CONFIG_HTTP_SERVER framework. That framework's resource/service model
 * expects TLS credentials known at compile time; BSC's certs are loaded
 * at runtime from BACnet File objects, so this talks to the same
 * lower-level primitives (websocket_register(), tls_credential_add())
 * the HTTP server itself uses (see subsys/net/lib/http/http_server_ws.c)
 * directly, without the framework on top.
 *
 * ARCHITECTURE: one listener thread per server instance (currently just
 * the hub protocol - see BSC_SRV_INSTANCES_NUM) owns the listening
 * socket. It polls for a pending connection, accept()s it (which - per
 * Zephyr's TLS socket layer - performs the full TLS handshake
 * synchronously inside accept() itself, inheriting the sec_tag/
 * peer-verify config set on the listening socket via tls_clone()), does
 * the HTTP Upgrade handshake by hand, then hands the connection off to
 * its own dedicated service thread and immediately goes back to
 * accept()ing the next one - it never blocks servicing a connection
 * itself. CONFIG_BACNETSTACK_BSC_HUB_MAX_CONNECTIONS (zephyr/Kconfig)
 * sizes the connection table/thread pool - a board/deployment decision,
 * not a fixed platform limit: size it to what the board actually
 * deployed can afford (see that Kconfig's help text for the per-connection
 * RAM cost accounting). Direct-connect (BSC_WEBSOCKET_DIRECT_PROTOCOL) is
 * not implemented - this project compiles with node-switch disabled
 * (BSC_CONF_NODE_SWITCHES_NUM=0) and never calls bws_srv_start() for it.
 *
 * NOTE: verified end-to-end on real hardware against real BACnet/SC
 * clients, including the multi-connection case: 2 concurrent nodes
 * connected (CONFIG_BACNETSTACK_BSC_HUB_MAX_CONNECTIONS=2), with both
 * broadcast fan-out and direct unicast (RP/WP) traffic correctly routed
 * between them by bsc-hub-function.c through this transport. TLS
 * handshake + mutual client-cert verification + WS upgrade + BVLC-SC
 * Connect-Request/Accept all confirmed working for both connections
 * independently. Known open issue (not yet root-caused): the TLS accept
 * handshake itself is slow (order 10s observed on the EFM32PG26/mbedTLS
 * combination this was first tested on) - CONFIG_NET_SOCKETS_LOG_LEVEL_DBG
 * and CONFIG_MBEDTLS_MEMORY_DEBUG are the first suspects (both were
 * switched on for an earlier, now-resolved cert-parsing bug), along with
 * whether the Secure Element's hardware crypto acceleration is actually
 * engaged for ECDHE/ECDSA rather than falling back to software bignum.
 *
 * @copyright SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/websocket.h>
#include <zephyr/sys/base64.h>
#include <psa/crypto.h>
/* BACnet Stack defines - first */
#include "bacnet/bacdef.h"
#include "bacnet/bacenum.h"
/* BACnet Stack API */
#include "bacnet/datalink/bsc/websocket.h"
#include "bacnet/datalink/bsc/bsc-conf.h"

/* Logging module registration is already done in ports/zephyr/main.c */
#include "bacnet_osif/bacnet_log.h"
LOG_MODULE_DECLARE(bacnet, CONFIG_BACNETSTACK_LOG_LEVEL);

#define THIS_FILE "websocket-srv.c"

/* Only the hub-protocol server role is implemented - see file header. */
#define BSC_SRV_INSTANCES_NUM 1

/* Board/deployment-configurable - see zephyr/Kconfig's help text for the
 * per-connection RAM cost this multiplies (one TLS session + one thread
 * stack each). Flat pool shared across all BSC_SRV_INSTANCES_NUM server
 * instances (fine while that's fixed at 1 - would need
 * BSC_SRV_INSTANCES_NUM * this-many slots if a second protocol server
 * were ever added). */
#define BSC_SRV_MAX_CONNECTIONS CONFIG_BACNETSTACK_BSC_HUB_MAX_CONNECTIONS

/* How often the listener polls its listening socket for a pending
 * connection (absent any activity) to notice a pending bws_srv_stop().
 * Once a connection IS pending, the subsequent accept() call still does
 * the full TLS handshake synchronously and can itself block for up to
 * CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT (10s default) - a slow/stalled
 * peer mid-handshake delays bws_srv_stop() noticing by that much. Same
 * tradeoff websocket-cli.c accepts for its own poll loop, just applied
 * one layer earlier (accept() instead of send/recv). */
#define BSC_SRV_ACCEPT_POLL_TIMEOUT_MS 500

/* How often each connection's service loop wakes up (absent socket
 * activity) to notice a pending disconnect/send/stop request - mirrors
 * BSC_CLI_POLL_TIMEOUT_MS in websocket-cli.c exactly. */
#define BSC_SRV_POLL_TIMEOUT_MS 200

/* One dedicated TLS sec_tag per server instance (currently just the hub
 * server) - deliberately offset from websocket-cli.c's
 * BSC_CLI_TLS_SEC_TAG_BASE(100)+handle range so the two roles' tags never
 * collide, even though only one role is actually active in any given
 * project today. Shared by every accepted connection on that server
 * (tls_clone() propagates it from the listening socket) - unlike the
 * client port, connections don't get their own tag. */
#define BSC_SRV_TLS_SEC_TAG_BASE 200

/* Listener thread: cred setup + accept() (TLS handshake included) + HTTP
 * upgrade handshake (PSA SHA-1). Connection service threads: TLS record
 * recv/send + BVLC-SC/APDU decode/encode through the dispatch callback
 * chain, same depth as websocket-cli.c's per-connection thread - sized
 * identically for the same reason (see that file's comment on
 * BSC_CLI_THREAD_STACK_SIZE re: a stack-overflow crash on this MCU). Both
 * thread kinds use the same size for simplicity/safety margin.
 * Measured high-water mark after running 2 real connections for a while
 * (`kernel thread stacks`): connection threads used only ~1950/8192
 * bytes (24%), the listener ~2825/8192 (34%) - real margin exists in
 * this size, but given this codebase's own stack-overflow crash history
 * elsewhere, that margin is being kept rather than trimmed. */
#define BSC_SRV_THREAD_STACK_SIZE 8192
#define BSC_SRV_THREAD_PRIORITY 5

/* Scratch buffer for the raw HTTP Upgrade request text (request line +
 * headers, up to the blank line). BACnet/SC clients send a short,
 * fixed-shape request (see websocket-cli.c's own request builder) - this
 * is generous headroom, not a measured minimum. */
#define BSC_SRV_HTTP_REQUEST_BUF_LEN 1024
#define BSC_SRV_HTTP_RESPONSE_BUF_LEN 256
#define BSC_SRV_SEC_KEY_MAX_LEN 64

typedef enum {
    BSC_SRV_STATE_IDLE = 0,
    BSC_SRV_STATE_STARTING = 1,
    BSC_SRV_STATE_LISTENING = 2,
    BSC_SRV_STATE_STOPPING = 3
} BSC_SRV_STATE;

/* Per-accepted-connection state - one slot per concurrent connection,
 * BSC_SRV_MAX_CONNECTIONS of them. */
typedef struct {
    bool used; /* slot occupied - handshake in progress or service thread running */
    bool started; /* this slot's thread was k_thread_create()'d at least once
                    * this server lifetime - governs whether it's safe/valid
                    * to k_thread_join() it during shutdown; unlike `used`,
                    * stays true even after the connection ends, until the
                    * next bws_srv_start() memset()s everything fresh. */
    int tcp_sock;
    int ws_sock;
    bool stop_requested;
    bool want_send_data;
    bool can_send_data;
    uint8_t rx_buf[BSC_WEBSOCKET_RX_BUFFER_LEN];
    char peer_ip[46];
    uint16_t peer_port;
    char err_desc[BSC_WEBSOCKET_ERR_DESC_STR_MAX_LEN];
    BACNET_ERROR_CODE err_code;
    struct k_thread thread;
} BSC_SRV_CONN;

typedef struct {
    BSC_SRV_STATE state;
    BSC_WEBSOCKET_PROTOCOL proto;
    int port;
    int listen_sock;
    bool srv_stop_requested;
    BSC_WEBSOCKET_SRV_DISPATCH dispatch_func;
    void *user_param;
    size_t timeout_s;
    /* certs/key must stay valid for the server's entire lifetime (every
     * accept()'s TLS handshake references the sec_tag they're registered
     * under) - unlike websocket-cli.c's per-connection copies, this is a
     * per-server, start-to-stop copy. bws_srv_start()'s caller cannot be
     * assumed to keep its own buffers alive that long. */
    uint8_t ca_cert[2048];
    size_t ca_cert_size;
    uint8_t cert[2048];
    size_t cert_size;
    uint8_t key[2048];
    size_t key_size;
    struct k_thread listener_thread;
    BSC_SRV_CONN conns[BSC_SRV_MAX_CONNECTIONS];
} BSC_WEBSOCKET_SRV;

/* Global lock protecting the tables below - distinct from
 * bws_dispatch_lock()/unlock() (websocket-global.c), which only
 * serializes dispatch_func() invocations against each other. Mirrors
 * websocket-cli.c's bws_cli_mutex exactly, including the discipline of
 * releasing this one before ever calling dispatch_func() (bsc-socket.c's
 * dispatch handlers call back into bws_srv_* reentrantly, which need to
 * take this same mutex). */
K_MUTEX_DEFINE(bws_srv_mutex);

static BSC_WEBSOCKET_SRV bws_srv[BSC_SRV_INSTANCES_NUM];

K_THREAD_STACK_ARRAY_DEFINE(
    bws_srv_listener_stacks, BSC_SRV_INSTANCES_NUM, BSC_SRV_THREAD_STACK_SIZE);
/* Flat pool, not per-server-instance - fine while BSC_SRV_INSTANCES_NUM
 * is fixed at 1 (see that macro's comment). */
K_THREAD_STACK_ARRAY_DEFINE(
    bws_srv_conn_stacks, BSC_SRV_MAX_CONNECTIONS, BSC_SRV_THREAD_STACK_SIZE);

/* The only server instance currently supported is index 0, the hub
 * protocol - see BSC_SRV_INSTANCES_NUM's comment. */
static int bsc_srv_instance_for_proto(BSC_WEBSOCKET_PROTOCOL proto)
{
    return (proto == BSC_WEBSOCKET_HUB_PROTOCOL) ? 0 : -1;
}

/**
 * @brief Find and reserve a free connection slot.
 * @note Must be called with bws_srv_mutex held. Marks the slot `used`
 *  immediately (before the handshake even starts) so a second incoming
 *  connection can't race for the same slot while this one is still being
 *  set up.
 * @return slot index, or -1 if the server is at BSC_SRV_MAX_CONNECTIONS capacity
 */
static int bsc_srv_alloc_conn(BSC_WEBSOCKET_SRV *srv)
{
    int i;

    for (i = 0; i < BSC_SRV_MAX_CONNECTIONS; i++) {
        if (!srv->conns[i].used) {
            srv->conns[i].used = true;
            srv->conns[i].tcp_sock = -1;
            srv->conns[i].ws_sock = -1;
            srv->conns[i].stop_requested = false;
            srv->conns[i].want_send_data = false;
            srv->conns[i].can_send_data = false;
            srv->conns[i].err_code = ERROR_CODE_SUCCESS;
            srv->conns[i].err_desc[0] = 0;
            srv->conns[i].peer_ip[0] = 0;
            srv->conns[i].peer_port = 0;
            return i;
        }
    }
    return -1;
}

static void bsc_srv_report_err(
    BSC_SRV_CONN *conn, BACNET_ERROR_CODE code, const char *desc)
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

/**
 * @brief Send an entire buffer, looping on short writes.
 * @return true if all bytes were sent
 */
static bool bsc_srv_sendall(int sock, const char *buf, size_t len)
{
    size_t sent = 0;
    int rc;

    while (sent < len) {
        rc = zsock_send(sock, &buf[sent], len - sent, 0);
        if (rc <= 0) {
            return false;
        }
        sent += (size_t)rc;
    }
    return true;
}

/**
 * @brief Read HTTP request headers (up to and including the blank line)
 *  from an accepted socket, and extract the Sec-WebSocket-Key header
 *  value and whether Sec-WebSocket-Protocol matches expected_protocol.
 * @return true if a well-formed websocket upgrade request was read
 */
static bool bsc_srv_read_http_upgrade_request(
    int sock,
    char *sec_key_out,
    size_t sec_key_out_len,
    bool *protocol_ok,
    const char *expected_protocol)
{
    static char req_buf[BSC_SRV_HTTP_REQUEST_BUF_LEN];
    size_t total = 0;
    char *header_end;
    char *line;
    char *line_end;

    *protocol_ok = false;
    sec_key_out[0] = 0;

    /* Accumulate bytes until the blank line terminating the HTTP headers
     * (RFC 7230 3) is seen, or the buffer fills, or recv() fails/times
     * out (SO_RCVTIMEO is set on this socket by the caller). A client
     * that pipelines websocket frames before the 101 response is not
     * supported - reasonable for BACnet/SC clients, which wait for the
     * handshake to complete first (see websocket-cli.c's own client-side
     * request/response handling, which does the same). */
    header_end = NULL;
    while (total < sizeof(req_buf) - 1) {
        int rc = zsock_recv(sock, &req_buf[total], sizeof(req_buf) - 1 - total, 0);

        if (rc <= 0) {
            /* rc == 0: peer closed the TCP connection without sending a
             * request. rc < 0 with errno == EAGAIN/ETIMEDOUT: SO_RCVTIMEO
             * (set by the caller from Network_Port_SC_Connect_Wait_Timeout)
             * expired waiting for the client to send its upgrade request. */
            LOG_WRN(
                "%s:%d - recv() on accepted socket returned %d (errno %d) "
                "after %u bytes - peer closed or handshake read timed out",
                THIS_FILE, __LINE__, rc, errno, (unsigned)total);
            return false;
        }
        total += (size_t)rc;
        req_buf[total] = 0;
        header_end = strstr(req_buf, "\r\n\r\n");
        if (header_end) {
            break;
        }
    }
    if (!header_end) {
        LOG_WRN(
            "%s:%d - HTTP upgrade request too large or missing terminator "
            "(%u bytes buffered)",
            THIS_FILE, __LINE__, (unsigned)total);
        return false;
    }
    LOG_DBG(
        "%s:%d - HTTP upgrade request received (%u bytes): %.60s...",
        THIS_FILE, __LINE__, (unsigned)total, req_buf);
    header_end[2] = 0; /* truncate after the header section's own \r\n */

    /* First line is the request line (e.g. "GET / HTTP/1.1") - skip it
     * and walk the remaining \r\n-separated header lines. */
    line = strstr(req_buf, "\r\n");
    if (!line) {
        return false;
    }
    line += 2;
    while (line < header_end) {
        char *colon;
        char *value;

        line_end = strstr(line, "\r\n");
        if (!line_end) {
            break;
        }
        *line_end = 0;
        colon = strchr(line, ':');
        if (colon) {
            *colon = 0;
            value = colon + 1;
            while (*value == ' ') {
                value++;
            }
            if (strcasecmp(line, "Sec-WebSocket-Key") == 0) {
                strncpy(sec_key_out, value, sec_key_out_len - 1);
                sec_key_out[sec_key_out_len - 1] = 0;
            } else if (strcasecmp(line, "Sec-WebSocket-Protocol") == 0) {
                *protocol_ok = (strcmp(value, expected_protocol) == 0);
            }
        }
        line = line_end + 2;
    }
    return sec_key_out[0] != 0;
}

/**
 * @brief Compute Sec-WebSocket-Accept from a Sec-WebSocket-Key per
 *  RFC 6455 4.2.2, the same PSA-SHA1 + base64 approach Zephyr's own HTTP
 *  server websocket upgrade uses (subsys/net/lib/http/http_server_ws.c).
 */
static bool bsc_srv_compute_ws_accept(
    const char *sec_key, char *accept_out, size_t accept_out_len)
{
    static const char ws_magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char key_and_magic[BSC_SRV_SEC_KEY_MAX_LEN + sizeof(ws_magic)];
    uint8_t digest[20];
    size_t digest_len;
    size_t key_len = strlen(sec_key);
    size_t olen;
    psa_status_t status;

    if (key_len == 0 || key_len >= BSC_SRV_SEC_KEY_MAX_LEN) {
        return false;
    }
    memcpy(key_and_magic, sec_key, key_len);
    memcpy(key_and_magic + key_len, ws_magic, sizeof(ws_magic) - 1);

    status = psa_hash_compute(
        PSA_ALG_SHA_1, (uint8_t *)key_and_magic, key_len + sizeof(ws_magic) - 1,
        digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS) {
        LOG_ERR(
            "%s:%d - psa_hash_compute() failed: %d", THIS_FILE, __LINE__,
            (int)status);
        return false;
    }
    if (base64_encode(
            (uint8_t *)accept_out, accept_out_len, &olen, digest,
            digest_len) != 0) {
        LOG_ERR("%s:%d - base64_encode() failed", THIS_FILE, __LINE__);
        return false;
    }
    accept_out[olen] = 0;
    return true;
}

/**
 * @brief Do the server side of the RFC 6455 HTTP Upgrade handshake on an
 *  already-accepted (already TLS-handshaked) socket.
 * @return the negotiated websocket fd (>= 0, from websocket_register()),
 *  or a negative error code
 */
static int bsc_srv_do_handshake(
    int tcp_sock, BSC_WEBSOCKET_SRV *srv, BSC_SRV_CONN *conn)
{
    char sec_key[BSC_SRV_SEC_KEY_MAX_LEN];
    char accept_key[32];
    char resp[BSC_SRV_HTTP_RESPONSE_BUF_LEN];
    bool protocol_ok;
    const char *expected_protocol =
        (srv->proto == BSC_WEBSOCKET_HUB_PROTOCOL)
            ? BSC_WEBSOCKET_HUB_PROTOCOL_STR
            : BSC_WEBSOCKET_DIRECT_PROTOCOL_STR;
    int len;

    if (!bsc_srv_read_http_upgrade_request(
            tcp_sock, sec_key, sizeof(sec_key), &protocol_ok,
            expected_protocol)) {
        /* bsc_srv_read_http_upgrade_request() already logged the specific
         * reason (recv() timeout/closed, or no blank-line terminator). */
        bsc_srv_sendall(
            tcp_sock, "HTTP/1.1 400 Bad Request\r\n\r\n",
            strlen("HTTP/1.1 400 Bad Request\r\n\r\n"));
        return -EPROTO;
    }
    if (!protocol_ok) {
        LOG_WRN(
            "%s:%d - request read OK but Sec-WebSocket-Protocol did not "
            "match the expected \"%s\" (missing, or a different value) - "
            "check the client is actually asking for this protocol",
            THIS_FILE, __LINE__, expected_protocol);
        bsc_srv_sendall(
            tcp_sock, "HTTP/1.1 400 Bad Request\r\n\r\n",
            strlen("HTTP/1.1 400 Bad Request\r\n\r\n"));
        return -EPROTO;
    }
    LOG_DBG(
        "%s:%d - Sec-WebSocket-Key=\"%s\" protocol=\"%s\" ok - computing "
        "Sec-WebSocket-Accept and sending 101 response",
        THIS_FILE, __LINE__, sec_key, expected_protocol);
    if (!bsc_srv_compute_ws_accept(sec_key, accept_key, sizeof(accept_key))) {
        return -EIO;
    }

    len = snprintf(
        resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Sec-WebSocket-Protocol: %s\r\n"
        "\r\n",
        accept_key, expected_protocol);
    if (len < 0 || (size_t)len >= sizeof(resp)) {
        return -EIO;
    }
    if (!bsc_srv_sendall(tcp_sock, resp, (size_t)len)) {
        LOG_WRN("%s:%d - failed to send 101 response", THIS_FILE, __LINE__);
        return -EIO;
    }
    return websocket_register(tcp_sock, conn->rx_buf, sizeof(conn->rx_buf));
}

/**
 * @brief Receive and dispatch one complete websocket message, if any is
 *  available within the given poll timeout. Mirrors
 *  bsc_cli_service_recv() in websocket-cli.c exactly.
 * @return false if the connection should be torn down
 */
static bool bsc_srv_service_recv(
    BSC_WEBSOCKET_SRV *srv, BSC_SRV_CONN *conn, int handle)
{
    uint32_t message_type = 0;
    uint64_t remaining = 0;
    size_t total = 0;
    int rc;
    BSC_WEBSOCKET_SRV_DISPATCH dispatch_func;
    void *user_param;

    do {
        rc = websocket_recv_msg(
            conn->ws_sock, &conn->rx_buf[total], sizeof(conn->rx_buf) - total,
            &message_type, &remaining, 0);
        if (rc == -EAGAIN) {
            return true;
        }
        if (rc < 0) {
            LOG_WRN(
                "%s:%d - connection %d: websocket_recv_msg() error %d",
                THIS_FILE, __LINE__, handle, rc);
            bsc_srv_report_err(conn, ERROR_CODE_WEBSOCKET_ERROR, NULL);
            return false;
        }
        total += (size_t)rc;
        if (message_type & WEBSOCKET_FLAG_CLOSE) {
            LOG_INF(
                "%s:%d - connection %d: peer closed websocket", THIS_FILE,
                __LINE__, handle);
            bsc_srv_report_err(conn, ERROR_CODE_WEBSOCKET_CLOSED_BY_PEER, NULL);
            return false;
        }
        if (total >= sizeof(conn->rx_buf) && remaining > 0) {
            LOG_WRN(
                "%s:%d - connection %d: message exceeds RX buffer (%u), "
                "dropped",
                THIS_FILE, __LINE__, handle, (unsigned)sizeof(conn->rx_buf));
            bsc_srv_report_err(conn, ERROR_CODE_WEBSOCKET_FRAME_TOO_LONG, NULL);
            return false;
        }
    } while (remaining > 0);

    if (!(message_type & WEBSOCKET_FLAG_BINARY)) {
        /* AB.7.5.3 BACnet/SC BVLC Message Exchange: a non-binary data
         * frame must cause the connection to be closed. */
        LOG_WRN(
            "%s:%d - connection %d: non-binary frame received, closing",
            THIS_FILE, __LINE__, handle);
        bsc_srv_report_err(conn, ERROR_CODE_WEBSOCKET_DATA_NOT_ACCEPTED, NULL);
        return false;
    }

    LOG_DBG(
        "%s:%d - connection %d: received %u bytes (BVLC-SC frame) from "
        "peer, dispatching to BACnet/SC layer",
        THIS_FILE, __LINE__, handle, (unsigned)total);
    dispatch_func = srv->dispatch_func;
    user_param = srv->user_param;
    k_mutex_unlock(&bws_srv_mutex);
    bws_dispatch_lock();
    dispatch_func(
        srv, handle, BSC_WEBSOCKET_RECEIVED, 0, NULL, conn->rx_buf, total,
        user_param);
    bws_dispatch_unlock();
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    return true;
}

/**
 * @brief Per-connection service thread entry point: dispatches CONNECTED,
 *  services recv/send until disconnected/stopped, dispatches
 *  DISCONNECTED, frees the slot.
 */
static void bws_srv_conn_thread_entry(void *p1, void *p2, void *p3)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)p1;
    int handle = (int)(intptr_t)p2;
    BSC_SRV_CONN *conn = &srv->conns[handle];
    ARG_UNUSED(p3);
    BSC_WEBSOCKET_SRV_DISPATCH dispatch_func;
    void *user_param;
    struct sockaddr_in peer_addr = { 0 };
    socklen_t peer_addr_len = sizeof(peer_addr);

    k_mutex_lock(&bws_srv_mutex, K_FOREVER);

    if (zsock_getpeername(
            conn->tcp_sock, (struct sockaddr *)&peer_addr, &peer_addr_len) ==
        0) {
        zsock_inet_ntop(
            AF_INET, &peer_addr.sin_addr, conn->peer_ip, sizeof(conn->peer_ip));
        conn->peer_port = ntohs(peer_addr.sin_port);
    }

    dispatch_func = srv->dispatch_func;
    user_param = srv->user_param;
    k_mutex_unlock(&bws_srv_mutex);
    bws_dispatch_lock();
    dispatch_func(srv, handle, BSC_WEBSOCKET_CONNECTED, 0, NULL, NULL, 0, user_param);
    bws_dispatch_unlock();
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);

    /* A dispatch handler above (bsc_dispatch_srv_func()'s CONNECTED
     * branch in bsc-socket.c) can call bws_srv_disconnect() reentrantly,
     * right here, before this loop ever runs once - conn->stop_requested
     * being set already is exactly that case, and the while condition
     * below picks it up on its very first check. */
    if (conn->stop_requested || srv->srv_stop_requested) {
        LOG_WRN(
            "%s:%d - connection %d: disconnect was requested BEFORE the "
            "service loop ran even once (reentrant, from within the "
            "CONNECTED dispatch callback itself) - the BACnet/SC layer "
            "rejected this connection immediately, not this transport port",
            THIS_FILE, __LINE__, handle);
    }
    while (!conn->stop_requested && !srv->srv_stop_requested) {
        struct zsock_pollfd fds[1];
        bool wake_for_send = conn->want_send_data;
        int rc;

        fds[0].fd = conn->ws_sock;
        fds[0].events = ZSOCK_POLLIN | (wake_for_send ? ZSOCK_POLLOUT : 0);
        fds[0].revents = 0;
        k_mutex_unlock(&bws_srv_mutex);
        rc = zsock_poll(fds, 1, BSC_SRV_POLL_TIMEOUT_MS);
        k_mutex_lock(&bws_srv_mutex, K_FOREVER);

        if (conn->stop_requested || srv->srv_stop_requested) {
            break;
        }
        if (rc < 0) {
            LOG_WRN(
                "%s:%d - connection %d: poll() error: %d", THIS_FILE,
                __LINE__, handle, errno);
            bsc_srv_report_err(conn, ERROR_CODE_WEBSOCKET_ERROR, "poll error");
            break;
        }
        if (rc == 0) {
            continue;
        }
        if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP | ZSOCK_POLLNVAL)) {
            bsc_srv_report_err(conn, ERROR_CODE_WEBSOCKET_CLOSED_BY_PEER, NULL);
            break;
        }
        if (fds[0].revents & ZSOCK_POLLIN) {
            if (!bsc_srv_service_recv(srv, conn, handle)) {
                break;
            }
        }
        if ((fds[0].revents & ZSOCK_POLLOUT) && conn->want_send_data) {
            conn->can_send_data = true;
            dispatch_func = srv->dispatch_func;
            user_param = srv->user_param;
            k_mutex_unlock(&bws_srv_mutex);
            bws_dispatch_lock();
            dispatch_func(
                srv, handle, BSC_WEBSOCKET_SENDABLE, 0, NULL, NULL, 0,
                user_param);
            bws_dispatch_unlock();
            k_mutex_lock(&bws_srv_mutex, K_FOREVER);
            conn->want_send_data = false;
            conn->can_send_data = false;
        }
    }

    dispatch_func = srv->dispatch_func;
    user_param = srv->user_param;
    {
        BACNET_ERROR_CODE err_code = conn->err_code;
        char err_desc[BSC_WEBSOCKET_ERR_DESC_STR_MAX_LEN];

        memcpy(err_desc, conn->err_desc, sizeof(err_desc));

        LOG_INF(
            "%s:%d - connection %d: tearing down (stop_requested=%d "
            "srv_stop_requested=%d err_code=%d err_desc=\"%s\")",
            THIS_FILE, __LINE__, handle, conn->stop_requested,
            srv->srv_stop_requested, (int)err_code, err_desc);

        /* websocket_unregister(), not websocket_disconnect(): the latter
         * only closes the websocket-layer fd, leaking the underlying TLS
         * context/socket - the exact bug websocket-cli.c's
         * bsc_cli_close_sockets() comment already found the hard way. */
        if (conn->ws_sock >= 0) {
            websocket_unregister(conn->ws_sock);
            conn->ws_sock = -1;
            conn->tcp_sock = -1; /* closed together with ws_sock above */
        } else if (conn->tcp_sock >= 0) {
            zsock_close(conn->tcp_sock);
            conn->tcp_sock = -1;
        }
        k_mutex_unlock(&bws_srv_mutex);

        bws_dispatch_lock();
        dispatch_func(
            srv, handle, BSC_WEBSOCKET_DISCONNECTED, err_code,
            err_code != ERROR_CODE_SUCCESS ? err_desc : NULL, NULL, 0,
            user_param);
        bws_dispatch_unlock();
    }

    /* Only now safe to free this slot for reuse - same reentrancy hazard
     * websocket-cli.c's bws_cli_thread_entry() documents: a dispatch
     * handler above can synchronously trigger a new connection that
     * would want this exact slot. Deliberately NOT clearing `started` -
     * bws_srv_stop()'s shutdown path uses it to know whether this slot's
     * thread is ever safe to k_thread_join(). */
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    conn->used = false;
    k_mutex_unlock(&bws_srv_mutex);
}

static void bws_srv_listener_thread_entry(void *p1, void *p2, void *p3)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)p1;
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);
    sec_tag_t sec_tag = BSC_SRV_TLS_SEC_TAG_BASE + (srv - bws_srv);
    sec_tag_t sec_tag_list[1] = { sec_tag };
    struct sockaddr_in addr = { 0 };
    BSC_WEBSOCKET_SRV_DISPATCH dispatch_func;
    void *user_param;
    int rc;
    int i;

    tls_credential_delete(sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PRIVATE_KEY);
    rc = tls_credential_add(
        sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE, srv->ca_cert,
        srv->ca_cert_size);
    if (rc == 0) {
        rc = tls_credential_add(
            sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE, srv->cert,
            srv->cert_size);
    }
    if (rc == 0) {
        rc = tls_credential_add(
            sec_tag, TLS_CREDENTIAL_PRIVATE_KEY, srv->key, srv->key_size);
    }
    if (rc < 0) {
        LOG_ERR(
            "%s:%d - tls_credential_add() failed: %d", THIS_FILE, __LINE__,
            rc);
        goto fail_no_socket;
    }

    srv->listen_sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (srv->listen_sock < 0) {
        LOG_ERR("%s:%d - socket() failed: %d", THIS_FILE, __LINE__, errno);
        goto fail_creds;
    }

    {
        int reuse = 1;

        zsock_setsockopt(
            srv->listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
            sizeof(reuse));
    }
    rc = zsock_setsockopt(
        srv->listen_sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list,
        sizeof(sec_tag_list));
    if (rc == 0) {
        /* Mutual TLS: BACnet/SC requires the hub to verify the
         * connecting node's client certificate against the CA chain
         * registered above. Confirmed working against a real client. */
        int peer_verify = TLS_PEER_VERIFY_REQUIRED;

        rc = zsock_setsockopt(
            srv->listen_sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify,
            sizeof(peer_verify));
    }
    if (rc != 0) {
        LOG_ERR(
            "%s:%d - TLS sockopt setup failed: %d", THIS_FILE, __LINE__,
            errno);
        goto fail_close_listen;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)srv->port);
    addr.sin_addr.s_addr = INADDR_ANY;
    /* iface binding (bws_srv_start()'s iface param) is not implemented -
     * always binds all interfaces. Not exercised today: bacnet_sch's
     * Network_Port_SC_Hub_Function_Binding_Set() passes a bare port with
     * no interface name. */
    rc = zsock_bind(srv->listen_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        LOG_ERR(
            "%s:%d - bind() to port %d failed: %d", THIS_FILE, __LINE__,
            srv->port, errno);
        goto fail_close_listen;
    }
    /* Backlog sized to the connection pool: a burst of up to N pending
     * TCP connections can queue at the OS level while the listener works
     * through accept()+handshake for each in turn. */
    rc = zsock_listen(srv->listen_sock, BSC_SRV_MAX_CONNECTIONS);
    if (rc != 0) {
        LOG_ERR("%s:%d - listen() failed: %d", THIS_FILE, __LINE__, errno);
        goto fail_close_listen;
    }
    /* This is the genuine "ready to accept" confirmation - main.c's own
     * "hub function started" log fires as soon as datalink_init()
     * returns, which (bws_srv_start() being asynchronous) can happen
     * before this thread has even gotten this far. */
    LOG_INF(
        "%s:%d - BSC hub server listening on port %d (fd=%d, mutual TLS "
        "required, max %d concurrent connections)",
        THIS_FILE, __LINE__, srv->port, srv->listen_sock,
        BSC_SRV_MAX_CONNECTIONS);

    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    srv->state = BSC_SRV_STATE_LISTENING;
    dispatch_func = srv->dispatch_func;
    user_param = srv->user_param;
    k_mutex_unlock(&bws_srv_mutex);

    bws_dispatch_lock();
    dispatch_func(
        srv, BSC_WEBSOCKET_INVALID_HANDLE, BSC_WEBSOCKET_SERVER_STARTED, 0,
        NULL, NULL, 0, user_param);
    bws_dispatch_unlock();

    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    while (!srv->srv_stop_requested) {
        struct zsock_pollfd fds[1] = { { .fd = srv->listen_sock,
                                          .events = ZSOCK_POLLIN } };
        int accepted;
        char peer_ip[46] = "?";
        uint16_t peer_port = 0;
        int slot;

        k_mutex_unlock(&bws_srv_mutex);
        rc = zsock_poll(fds, 1, BSC_SRV_ACCEPT_POLL_TIMEOUT_MS);
        k_mutex_lock(&bws_srv_mutex, K_FOREVER);

        if (srv->srv_stop_requested) {
            break;
        }
        if (rc <= 0 || !(fds[0].revents & ZSOCK_POLLIN)) {
            continue;
        }

        /* Proves a TCP SYN reached this device's listening socket -
         * before accept()/the TLS handshake even happens. If your client
         * never gets you here, the problem is below the app (routing,
         * a firewall between the two devices, wrong port/hostname on the
         * client side, or the listen line above never having appeared). */
        LOG_INF(
            "%s:%d - incoming TCP connection pending, calling accept() "
            "(TLS handshake next)",
            THIS_FILE, __LINE__);

        k_mutex_unlock(&bws_srv_mutex);
        /* accept() performs the full TLS handshake synchronously here
         * (Zephyr's ztls_accept_ctx(), inheriting this listening
         * socket's sec_tag/peer-verify config via tls_clone()) - can
         * block up to CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT. While this
         * one accept() is in progress, already-connected peers keep
         * being serviced normally by their own dedicated threads - only
         * a *new* connection attempt has to wait behind this. */
        accepted = zsock_accept(srv->listen_sock, NULL, NULL);
        k_mutex_lock(&bws_srv_mutex, K_FOREVER);

        if (accepted < 0) {
            LOG_WRN(
                "%s:%d - accept() failed (TLS handshake or client cert "
                "verification rejected it - the TCP connection did reach "
                "this device): %d",
                THIS_FILE, __LINE__, errno);
            continue;
        }

        {
            struct sockaddr_in peer = { 0 };
            socklen_t peer_len = sizeof(peer);

            if (zsock_getpeername(
                    accepted, (struct sockaddr *)&peer, &peer_len) == 0) {
                zsock_inet_ntop(
                    AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
                peer_port = ntohs(peer.sin_port);
            }
            LOG_INF(
                "%s:%d - accept() succeeded from %s:%u (TCP+TLS handshake "
                "and client cert verification passed) - starting websocket "
                "upgrade handshake",
                THIS_FILE, __LINE__, peer_ip, (unsigned)peer_port);
        }

        if (srv->srv_stop_requested) {
            zsock_close(accepted);
            break;
        }

        slot = bsc_srv_alloc_conn(srv);
        if (slot < 0) {
            LOG_WRN(
                "%s:%d - at capacity (%d/%d connections in use) - "
                "rejecting new connection from %s:%u. Raise "
                "CONFIG_BACNETSTACK_BSC_HUB_MAX_CONNECTIONS if this board "
                "has the RAM to spare.",
                THIS_FILE, __LINE__, BSC_SRV_MAX_CONNECTIONS,
                BSC_SRV_MAX_CONNECTIONS, peer_ip, (unsigned)peer_port);
            k_mutex_unlock(&bws_srv_mutex);
            zsock_close(accepted);
            k_mutex_lock(&bws_srv_mutex, K_FOREVER);
            continue;
        }

        srv->conns[slot].tcp_sock = accepted;
        {
            struct zsock_timeval tv = {
                .tv_sec = (long)srv->timeout_s, .tv_usec = 0
            };

            zsock_setsockopt(
                accepted, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            zsock_setsockopt(
                accepted, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        k_mutex_unlock(&bws_srv_mutex);
        rc = bsc_srv_do_handshake(accepted, srv, &srv->conns[slot]);
        k_mutex_lock(&bws_srv_mutex, K_FOREVER);

        if (rc < 0) {
            LOG_WRN(
                "%s:%d - connection %d: websocket upgrade handshake "
                "failed: %d",
                THIS_FILE, __LINE__, slot, rc);
            zsock_close(accepted);
            srv->conns[slot].tcp_sock = -1;
            srv->conns[slot].used = false;
            continue;
        }
        srv->conns[slot].ws_sock = rc;
        srv->conns[slot].started = true;
        k_thread_create(
            &srv->conns[slot].thread, bws_srv_conn_stacks[slot],
            K_THREAD_STACK_SIZEOF(bws_srv_conn_stacks[slot]),
            bws_srv_conn_thread_entry, srv, (void *)(intptr_t)slot, NULL,
            BSC_SRV_THREAD_PRIORITY, 0, K_NO_WAIT);
        k_thread_name_set(&srv->conns[slot].thread, "bsc_srv_conn");
        LOG_INF(
            "%s:%d - connection %d: websocket upgrade handshake complete - "
            "service thread started",
            THIS_FILE, __LINE__, slot);
        /* Deliberately does NOT block servicing this connection - loops
         * straight back to poll()/accept() for the next one. */
    }

    /* Shutting down: every still-`used` connection was already flagged
     * via conn->stop_requested by bws_srv_stop() (it sets this on all
     * slots directly, since it - not this loop - holds the lock at the
     * moment srv_stop_requested transitions to true). Join every slot
     * that was ever started, unlocking around each join since the
     * connection thread being joined needs this same mutex to finish its
     * own teardown (see bws_srv_conn_thread_entry()'s tail). */
    for (i = 0; i < BSC_SRV_MAX_CONNECTIONS; i++) {
        if (srv->conns[i].started) {
            k_mutex_unlock(&bws_srv_mutex);
            k_thread_join(&srv->conns[i].thread, K_FOREVER);
            k_mutex_lock(&bws_srv_mutex, K_FOREVER);
            srv->conns[i].started = false;
        }
    }

    dispatch_func = srv->dispatch_func;
    user_param = srv->user_param;
    zsock_close(srv->listen_sock);
    srv->listen_sock = -1;
    k_mutex_unlock(&bws_srv_mutex);

    tls_credential_delete(sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PRIVATE_KEY);

    bws_dispatch_lock();
    dispatch_func(
        srv, BSC_WEBSOCKET_INVALID_HANDLE, BSC_WEBSOCKET_SERVER_STOPPED, 0,
        NULL, NULL, 0, user_param);
    bws_dispatch_unlock();

    /* Only now safe to recycle this instance - same reentrancy hazard
     * websocket-cli.c's bws_cli_thread_entry() documents: a dispatch
     * handler above can synchronously call bws_srv_start() again. */
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    srv->state = BSC_SRV_STATE_IDLE;
    k_mutex_unlock(&bws_srv_mutex);
    return;

fail_close_listen:
    zsock_close(srv->listen_sock);
    srv->listen_sock = -1;
fail_creds:
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
    tls_credential_delete(sec_tag, TLS_CREDENTIAL_PRIVATE_KEY);
fail_no_socket:
    /* No SERVER_STARTED was ever dispatched, so no SERVER_STOPPED either -
     * bsc_init_ctx() (bsc-socket.c) only calls bws_srv_start() once and
     * gives up on any non-BSC_WEBSOCKET_SUCCESS return; since that return
     * already happened (bws_srv_start() returns BSC_WEBSOCKET_SUCCESS
     * before this thread even runs, matching the async contract
     * bws_cli_connect() also uses), there is nothing more to report here
     * except via the log. */
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    srv->state = BSC_SRV_STATE_IDLE;
    k_mutex_unlock(&bws_srv_mutex);
}

BSC_WEBSOCKET_RET bws_srv_start(
    BSC_WEBSOCKET_PROTOCOL proto,
    int port,
    char *iface,
    uint8_t *ca_cert,
    size_t ca_cert_size,
    uint8_t *cert,
    size_t cert_size,
    uint8_t *key,
    size_t key_size,
    size_t timeout_s,
    BSC_WEBSOCKET_SRV_DISPATCH dispatch_func,
    void *dispatch_func_user_param,
    BSC_WEBSOCKET_SRV_HANDLE *sh)
{
    int idx = bsc_srv_instance_for_proto(proto);
    BSC_WEBSOCKET_SRV *srv;

    if (idx < 0) {
        LOG_ERR(
            "%s:%d - bws_srv_start(): only BSC_WEBSOCKET_HUB_PROTOCOL is "
            "implemented by this Zephyr port (direct-connect server role "
            "is not)",
            THIS_FILE, __LINE__);
        return BSC_WEBSOCKET_NO_RESOURCES;
    }
    if (!ca_cert || !ca_cert_size || !cert || !cert_size || !key ||
        !key_size || port <= 0 || !timeout_s || !dispatch_func || !sh) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    if (ca_cert_size > sizeof(bws_srv[0].ca_cert) ||
        cert_size > sizeof(bws_srv[0].cert) ||
        key_size > sizeof(bws_srv[0].key)) {
        LOG_ERR(
            "%s:%d - credential too large for fixed buffers", THIS_FILE,
            __LINE__);
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    ARG_UNUSED(iface);

    *sh = NULL;
    srv = &bws_srv[idx];

    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    if (srv->state != BSC_SRV_STATE_IDLE) {
        k_mutex_unlock(&bws_srv_mutex);
        return BSC_WEBSOCKET_NO_RESOURCES;
    }
    memset(srv, 0, sizeof(*srv));
    srv->state = BSC_SRV_STATE_STARTING;
    srv->proto = proto;
    srv->port = port;
    srv->listen_sock = -1;
    srv->timeout_s = timeout_s;
    srv->dispatch_func = dispatch_func;
    srv->user_param = dispatch_func_user_param;
    memcpy(srv->ca_cert, ca_cert, ca_cert_size);
    srv->ca_cert_size = ca_cert_size;
    memcpy(srv->cert, cert, cert_size);
    srv->cert_size = cert_size;
    memcpy(srv->key, key, key_size);
    srv->key_size = key_size;

    k_thread_create(
        &srv->listener_thread, bws_srv_listener_stacks[idx],
        K_THREAD_STACK_SIZEOF(bws_srv_listener_stacks[idx]),
        bws_srv_listener_thread_entry, srv, NULL, NULL,
        BSC_SRV_THREAD_PRIORITY, 0, K_NO_WAIT);
    k_thread_name_set(&srv->listener_thread, "bsc_srv_listen");

    *sh = (BSC_WEBSOCKET_SRV_HANDLE)srv;
    k_mutex_unlock(&bws_srv_mutex);
    return BSC_WEBSOCKET_SUCCESS;
}

BSC_WEBSOCKET_RET bws_srv_stop(BSC_WEBSOCKET_SRV_HANDLE sh)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)sh;
    int i;

    if (!srv) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    if (srv->state == BSC_SRV_STATE_IDLE) {
        k_mutex_unlock(&bws_srv_mutex);
        return BSC_WEBSOCKET_SUCCESS;
    }
    /* Asynchronous, like bws_cli_disconnect(): just signal. The listener
     * thread (and, via the flags set below, every connection thread)
     * notices within BSC_SRV_ACCEPT_POLL_TIMEOUT_MS/BSC_SRV_POLL_TIMEOUT_MS
     * and unwinds on its own, dispatching SERVER_STOPPED once everything
     * is joined - bsc_deinit_ctx() (bsc-socket.c) expects exactly this
     * async contract and does not block waiting here. */
    srv->srv_stop_requested = true;
    for (i = 0; i < BSC_SRV_MAX_CONNECTIONS; i++) {
        srv->conns[i].stop_requested = true;
    }
    k_mutex_unlock(&bws_srv_mutex);
    return BSC_WEBSOCKET_SUCCESS;
}

void bws_srv_disconnect(BSC_WEBSOCKET_SRV_HANDLE sh, BSC_WEBSOCKET_HANDLE h)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)sh;

    if (!srv || h < 0 || h >= BSC_SRV_MAX_CONNECTIONS) {
        return;
    }
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    /* Called by bsc-socket.c whenever the BACnet/SC layer above this
     * transport wants a connection dropped - most notably, reentrantly,
     * from within its own CONNECTED dispatch handler if
     * bsc_find_free_socket() finds no free BSC_SOCKET slot. */
    LOG_INF(
        "%s:%d - bws_srv_disconnect() called for connection %d, used=%d",
        THIS_FILE, __LINE__, h, srv->conns[h].used);
    if (srv->conns[h].used) {
        srv->conns[h].stop_requested = true;
    }
    k_mutex_unlock(&bws_srv_mutex);
}

void bws_srv_send(BSC_WEBSOCKET_SRV_HANDLE sh, BSC_WEBSOCKET_HANDLE h)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)sh;

    if (!srv || h < 0 || h >= BSC_SRV_MAX_CONNECTIONS) {
        return;
    }
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    if (srv->conns[h].used) {
        srv->conns[h].want_send_data = true;
    }
    k_mutex_unlock(&bws_srv_mutex);
}

BSC_WEBSOCKET_RET bws_srv_dispatch_send(
    BSC_WEBSOCKET_SRV_HANDLE sh,
    BSC_WEBSOCKET_HANDLE h,
    uint8_t *payload,
    size_t payload_size)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)sh;
    BSC_SRV_CONN *conn;
    BSC_WEBSOCKET_RET ret;
    int written;

    if (!srv || h < 0 || h >= BSC_SRV_MAX_CONNECTIONS) {
        return BSC_WEBSOCKET_BAD_PARAM;
    }
    conn = &srv->conns[h];

    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    if (!conn->used || !conn->want_send_data || !conn->can_send_data) {
        k_mutex_unlock(&bws_srv_mutex);
        return BSC_WEBSOCKET_INVALID_OPERATION;
    }

    /* Server-originated frames must NOT be masked per RFC 6455 5.1 (only
     * client-to-server frames are masked) - the one real asymmetry
     * versus websocket-cli.c's equivalent call. */
    written = websocket_send_msg(
        conn->ws_sock, payload, payload_size, WEBSOCKET_OPCODE_DATA_BINARY,
        false, true, (int32_t)(srv->timeout_s * 1000));

    if (written < (int)payload_size) {
        LOG_WRN(
            "%s:%d - connection %d: websocket_send_msg() short/failed "
            "write: %d",
            THIS_FILE, __LINE__, h, written);
        conn->stop_requested = true;
        ret = BSC_WEBSOCKET_INVALID_OPERATION;
    } else {
        LOG_DBG(
            "%s:%d - connection %d: sent %u bytes (BVLC-SC frame) to peer",
            THIS_FILE, __LINE__, h, (unsigned)payload_size);
        ret = BSC_WEBSOCKET_SUCCESS;
    }
    k_mutex_unlock(&bws_srv_mutex);
    return ret;
}

bool bws_srv_get_peer_ip_addr(
    BSC_WEBSOCKET_SRV_HANDLE sh,
    BSC_WEBSOCKET_HANDLE h,
    uint8_t *ip_str,
    size_t ip_str_len,
    uint16_t *port)
{
    BSC_WEBSOCKET_SRV *srv = (BSC_WEBSOCKET_SRV *)sh;
    BSC_SRV_CONN *conn;
    bool ok = false;

    if (!srv || !ip_str || !port || h < 0 || h >= BSC_SRV_MAX_CONNECTIONS) {
        return false;
    }
    conn = &srv->conns[h];
    k_mutex_lock(&bws_srv_mutex, K_FOREVER);
    if (conn->used && conn->peer_ip[0]) {
        strncpy((char *)ip_str, conn->peer_ip, ip_str_len - 1);
        ip_str[ip_str_len - 1] = 0;
        *port = conn->peer_port;
        ok = true;
    }
    k_mutex_unlock(&bws_srv_mutex);
    return ok;
}

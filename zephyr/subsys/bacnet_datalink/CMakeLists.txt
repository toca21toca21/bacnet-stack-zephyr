# Copyright (c) 2024 Legrand North America, LLC.
# SPDX-License-Identifier: Apache-2.0

zephyr_sources_ifdef(
  CONFIG_BACDL_BIP
  bip-init.c
)

zephyr_sources_ifdef(
  CONFIG_BACDL_BIP6
  bip6-init.c
)

# BACnet/SC transport port: bsc_init() (bsc-datalink.c, always compiled
# when CONFIG_BACDL_BSC is set) calls into bws_cli_*/bws_srv_*
# (bacnet/datalink/bsc/websocket.h) and bsc_event_*
# (bacnet/datalink/bsc/bsc-event.h), which have no Zephyr implementation
# upstream - only bsd/linux/win32 ports exist. These provide both roles
# over Zephyr's native websocket client/server + TLS sockets:
# websocket-cli.c for the client/hub-connector role (joining an existing
# hub, e.g. blinky_sc), websocket-srv.c for the server/hub-function role
# (hosting a hub and accepting node connections, e.g. bacnet_sch).
# websocket-srv.c only implements one hub-protocol server/one connection
# at a time (see its own file header) - harmless for a client-only
# project like blinky_sc, since bws_srv_* is simply never called there
# (SC_Hub_Function_Enable stays false).
zephyr_sources_ifdef(
  CONFIG_BACDL_BSC
  bsc-event.c
  websocket-global.c
  websocket-cli.c
  websocket-srv.c
)

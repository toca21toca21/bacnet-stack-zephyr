# CMake for the uBASIC+BACnet Program object subsystem
#
# @date 2026
# @copyright SPDX-License-Identifier: Apache-2.0
zephyr_interface_library_named(bacnet_ubasic)

zephyr_library()

# global, not zephyr_library_include_directories() - program-ubasic.h is
# consumed by application code (outside this library), not just by this
# subsystem's own sources
zephyr_include_directories_ifdef(CONFIG_BACNETSTACK_BACNET_UBASIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

zephyr_library_sources_ifdef(CONFIG_BACNETSTACK_BACNET_UBASIC
  ${BACNETSTACK_SRC}/bacnet/basic/program/ubasic/ubasic.c
  ${BACNETSTACK_SRC}/bacnet/basic/program/ubasic/tokenizer.c
  program-ubasic.c
  ubasic-port.c
)

# bacnet_ubasic — uBASIC+BACnet scripting subsystem

Zephyr port of bacnet-stack's `ports/stm32f4xx` uBASIC+BACnet reference: a small BASIC-family
interpreter, embedded directly into a BACnet device as a standard **Program** object, with its
source held in a standard **File** object. This document is the reference for *this port
specifically* — what it actually supports, its real constraints, and where it diverges from
upstream. It is a supplement to, not a replacement for, the upstream language reference at
`bacnet-stack`'s own `src/bacnet/basic/program/ubasic/README.md`, which is the authoritative
source for uBASIC-Plus syntax itself (flow control, string/math functions, 10 worked demos) —
read that first for the language, come back here for the BACnet integration, the deltas from that
reference implementation, and the numbers that actually bound scripts in this port.

## Architecture

- **`OBJECT_PROGRAM`** (standard object type `16`) represents one running script. Its standard
  `Program_State`/`Program_Change`/`Reason_For_Halt` properties are the *only* remote control
  surface — there is no proprietary object type or property anywhere in this design.
- **`OBJECT_FILE`** (standard object type `10`) holds the script's actual source text, genuinely
  network-writable via `AtomicWriteFile`/readable via `AtomicReadFile` — ordinary, unmodified
  BACnet File object behavior.
- The two are linked by convention, not a BACnet property: the app creates a File and a Program
  object with the *same* pathname, and the interpreter re-reads that File's current content on
  every `Load`/`Restart`. `Program_Instance_Of` (a standard, already-writable property) is set to
  the pathname purely as a discoverability breadcrumb for a client browsing the object — nothing
  reads it back internally.
- `program-ubasic.c` implements the Program object's `Load`/`Run`/`Halt`/`Restart`/`Unload`
  callbacks (the standard plugin-callback API `program.c` already provides — no edits to
  `program.c` itself were needed anywhere in this design). `ubasic-port.c` implements the
  interpreter's own hardware/BACnet callback layer (`struct ubasic_data`'s function pointers).
  The portable interpreter itself (`ubasic.c`/`tokenizer.c`, in the `bacnet-stack` module) is
  unmodified.

## Enabling it

```
CONFIG_BACNET_BASIC_OBJECT_PROGRAM=y
CONFIG_BACNET_BASIC_OBJECT_FILE=y
CONFIG_BACNETSTACK_BACNET_UBASIC=y
# plus whichever OBJECT types a script actually needs - see "Supported object types" below
```

Two sizing knobs (`subsys/bacnet_ubasic/Kconfig`):

| Kconfig | Default | Meaning |
|---|---|---|
| `BACNETSTACK_UBASIC_TASK_INTERVAL_MS` | 10 | How often `Program_UBASIC_Task()` ticks each running script, independent of the generic ~100ms object-housekeeping tick — scripts using `sleep()`/`tic()`/`toc()` want finer granularity than that. |
| `BACNETSTACK_UBASIC_SCRIPT_BUFFER_SIZE` | 512 | **The real per-script size ceiling — see "Size constraints" below, this one fails silently.** |

## Application integration pattern

There is no per-app Kconfig magic beyond the above — an app wires this in with plain C, following
`bacnet_ip_node_ubasic/src/main.c` as the reference:

1. `bacfile_ramfs_init()` — the dynamic, heap-backed File-object content store (as opposed to
   `bacfile_sramfs_init()`, the *read-only*, static variant the upstream stm32f4xx demo uses for
   its compiled-in scripts — a real product wants `ramfs`, not `sramfs`).
2. If persistence-to-flash is wanted, register a custom `bacfile_write_stream_data_callback_set()`
   wrapper **after** `bacfile_ramfs_init()` — it unconditionally reinstalls its own plain callback,
   so registering a wrapper before it gets silently clobbered. See
   `bacnet_ip_node_ubasic/src/main.c`'s `UBasic_File_Write_Stream_Persist()` for a working example
   (mirrors and re-persists the File's *entire current* content on every successful write, riding
   Zephyr's `settings` subsystem rather than a dedicated NVS partition).
3. Register `SERVICE_CONFIRMED_ATOMIC_READ_FILE`/`_WRITE_FILE` handlers — not auto-registered
   unless `CONFIG_BACNET_BASIC_BACKUP_RESTORE` is on.
4. `Program_UBASIC_Init(CONFIG_BACNETSTACK_UBASIC_TASK_INTERVAL_MS)` once.
5. Per script: `bacfile_create()` + `bacfile_pathname_set()`, optionally restore persisted content
   into `ramfs` (see step 2's example) *before* the next step, then
   `Program_UBASIC_Create(instance, &ubasic_data, fallback_program_text, pathname)`. The fallback
   text is only ever used if the File object is still empty at that point (first boot, nothing
   persisted yet) — a non-empty File always wins.
6. Call `Program_UBASIC_Task()` from the app's own periodic task callback (unconditionally — don't
   put it behind an early-return guard for unrelated hardware, e.g. a missing button GPIO).

## Remote deployment workflow

1. `AtomicWriteFile` new script bytes to the File object.
2. `WriteProperty` `4` (RESTART) to that Program instance's `Program_Change` (property `90`).
   `Program_Load()`/`Program_Restart()` re-read the File's *current* content each time — they do
   not replay a fixed creation-time snapshot.

| Property | ID | R/W | Values |
|---|---|---|---|
| `Program_Change` | 90 | W | `0`=READY `1`=LOAD `2`=RUN `3`=HALT `4`=RESTART `5`=UNLOAD |
| `Program_Location` | 91 | R | Locally-set descriptive text only — **never** a content channel, see below |
| `Program_State` | 92 | R | `0`=IDLE `1`=LOADING `2`=RUNNING `3`=WAITING `4`=HALTED `5`=UNLOADING |
| `Reason_For_Halt` | 100 | R | `0`=NORMAL `1`=LOAD_FAILED `2`=INTERNAL `3`=PROGRAM `4`=OTHER |
| `Instance_Of` | 48 | R | The linked File object's pathname |
| `File_Size` | 42 | R (this port) | Standard File object property |

**Live debugging, no console needed:** `Program_Location` is wired to the interpreter's own
`ubasic_program_location()` (the *currently executing statement's text*, refreshed every tick) —
`ReadProperty` on it at any time to see what line a running script is actually on. It reads mostly
blank on a tight, fast-cycling polling loop (catching the interpreter between statement
boundaries is common and expected, not a bug) and shows real statement text when the read happens
to land mid-execution.

**⚠ `Program_Location` was, briefly, mistakenly made network-*writable*** during this port's
development, reasoning "it's a CharacterString like `Description`, which is writable" — wrong, and
reverted. There is no standard mechanism for pushing content into a Program object at all; that's
deliberately left to vendor means (`Program_Context`, here: the linked File object +
`Instance_Of`). Don't repeat that mistake if extending this further — check a real reference
implementation's actual behavior before assuming a property is writable just because a
similarly-typed sibling property is.

## Supported object types — `bac_create`/`bac_read`/`bac_write`

```basic
bac_create(object_type, instance, name$)
h = bac_read(object_type, instance, property_id)
bac_write(object_type, instance, property_id, value)
```

| `object_type` | BACnet object | Kconfig to enable |
|---:|---|---|
| 0 | Analog Input | `BACNET_BASIC_OBJECT_ANALOG_INPUT` |
| 1 | Analog Output | `BACNET_BASIC_OBJECT_ANALOG_OUTPUT` |
| 2 | Analog Value | `BACNET_BASIC_OBJECT_ANALOG_VALUE` |
| 3 | Binary Input | `BACNET_BASIC_OBJECT_BINARY_INPUT` |
| 4 | Binary Output | `BACNET_BASIC_OBJECT_BINARY_OUTPUT` |
| 5 | Binary Value | `BACNET_BASIC_OBJECT_BINARY_VALUE` |
| 13 | Multi-State Input | `BACNET_BASIC_OBJECT_MULTISTATE_INPUT` |
| 14 | Multi-State Output | `BACNET_BASIC_OBJECT_MULTISTATE_OUTPUT` |
| 19 | Multi-State Value | `BACNET_BASIC_OBJECT_MULTISTATE_VALUE` |

These 9 are the *only* types `ubasic-port.c`'s `bacnet_create_object`/`_write_property`/
`_read_property` handle at all (each `switch` has a `default: break;` for anything else — an
unsupported `object_type` argument is silently a no-op, not an error). Each `case` is individually
`#if defined(CONFIG_BACNET_BASIC_OBJECT_X)`-guarded, so a script calling `bac_write` against a type
the running app didn't enable also silently no-ops, same as an unsupported type — **there is no
runtime error signal for either case**, a script author/checker needs the object-type table above
plus knowledge of the target app's actual `prj.conf`.

**`property_id` is a real parameter, but only `85` (`PROP_PRESENT_VALUE`) does anything** — every
`case` checks `if (property_id == PROP_PRESENT_VALUE)` and no-ops otherwise. **Write priority is
hardcoded to `BACNET_MAX_PRIORITY` (16)** for every commandable write — a script can never write at
a higher priority, nor relinquish (write `NULL`) at all. Extending both of these (arbitrary
property id, a real priority argument, possibly array-index) is tracked as deferred future work —
see the project's own memory notes for the reasoning (this was the original motivation for
reviving a proprietary "BACQL" language years ago; the plan now is to extend `bac_read`/
`bac_write` instead of reviving a separate parser).

`bac_write` on `OBJECT_BINARY_OUTPUT` specifically goes through `Binary_Output_Present_Value_Write()`
(exported from `bo.c` for this port), not the lower-level `_Set()` — that's what actually fires a
registered `Write_Present_Value_Callback` (e.g. driving a physical LED). Other object types'
equivalent local-write-vs-network-write split (`ao.c`/`av.c`/`bv.c`/`msv.c` almost certainly have
the same static-`_Write()`-vs-public-`_Set()` shape) has not been exported/fixed yet, since nothing
in this port currently registers a hardware callback for any of them — if a future device wires an
actuator to one of those, check for this exact gap first.

## `flag()`/hardware events

`flag(N)` (1-based in script syntax) reads/clears **bit N-1** internally
(`ubasic.c`: `hw_event(data, r - 1)`) — **do not set bit N for `flag(N)`, set bit N-1.** This bit an
easy off-by-one to reintroduce; it was found and fixed once already via live debugging.

This port does **not** wire a real GPIO interrupt for hardware events — `ubasic_port_hw_event_set()`
is called from whatever polling/debounce logic an app already has (e.g.
`bacnet_ip_node_ubasic/main.c`'s existing ~1ms-polled, debounced button handler), not from an ISR.
Deliberate: a real interrupt would need atomics (genuine ISR-vs-thread concurrency) for no latency
benefit over a loop that's already running every ~1ms.

## Known stubs / gaps (`ubasic-port.c`)

- **GPIO/ADC/PWM/serial console I/O** (`pinmode`/`dwrite`/`aread`/`awrite`/serial input) are
  explicit no-op stubs (`@todo` marked) — real board pin wiring is a per-target decision, not made
  here. A script using these keywords runs without error but nothing physically happens.
- Random number generation (`ran`/`uniform`) uses Zephyr's real `sys_rand32_get()` — genuinely
  working, not a stub.
- `store`/`recall` (persistent variable storage) is wired to a **volatile RAM scratch buffer**
  despite being named after EEPROM in the reference this was ported from — does **not** survive a
  reboot. Real NVS-backed variable persistence hasn't been built (script *source* persistence has,
  see the remote deployment section above — this is a separate, still-open piece).
- No signing or encryption on script content yet — a script written over the network today is
  exactly as trusted as the one it boots with. Deliberately deferred; the stated goal is parity
  with this device family's eventual FOTA security model, not an ad hoc scheme.

## Size constraints

| Constraint | Value | Where | Failure mode if exceeded |
|---|---:|---|---|
| Per-script source size | 512 bytes | `BACNETSTACK_UBASIC_SCRIPT_BUFFER_SIZE` (Kconfig) | **Silent** — `ubasic_reload_from_file()` falls back to the compiled-in bootstrap text instead of the oversized script. `AtomicWriteFile` acks fine; the write even persists to flash; the script that actually *runs* just silently doesn't change. No BACnet error, no log line. |
| AtomicWriteFile segment size | up to `CONFIG_BACNET_MAX_OCTET_STRING_BYTES` (app-set, e.g. 1400 in `bacnet_ip_node_ubasic`) | app `prj.conf` | Per-segment only, not a total-file cap - a client can segment a larger transfer, though the 512-byte script cap above makes this moot for uBASIC specifically. |
| APDU size | `BACNET_MAX_APDU_SIZE`, default 1476 | `zephyr/Kconfig` | Governs the real per-segment ceiling alongside the octet-string setting above. |
| One statement's length | 64 bytes | `UBASIC_STATEMENT_SIZE` (`ubasic/config.h`) | Not currently Kconfig-exposed. |
| One string literal/variable | 40 bytes | `UBASIC_STRINGLEN_MAX` | ″ |
| Total string scratch space (all string vars/temporaries combined, whole script) | 256 bytes | `UBASIC_STRING_BUFFER_LEN_MAX` | ″ |
| Numeric/string variables | 26 each (`a`-`z`, `a$`-`z$`) | `UBASIC_VARNUM_MAX` | Fixed language limit, not a buffer to size up easily. |
| Array storage (shared across all `@`-arrays in a script) | 64 elements | `UBASIC_VARIABLE_TYPE_ARRAY` | ″ |
| Label name length | 10 bytes | `UBASIC_LABEL_LEN_MAX` | ″ |
| Nesting depth: `for`/`while`/`if...endif` | 4 each | `UBASIC_*_STACK_DEPTH` | ″ |
| Nesting depth: `gosub` | 10 | `UBASIC_GOSUB_STACK_DEPTH` | ″ |
| Concurrent Program instances this port's internal binding table tracks | 8 | `UBASIC_MAX_INSTANCES` (`program-ubasic.c`, plain `#define`, not Kconfig) | Bump the `#define` if ever needed - not currently exposed as a build option. |

## A gotcha worth knowing before writing/generating scripts

The tokenizer treats `;` and `\n` as **exactly the same token** (`UBASIC_TOKENIZER_EOL`) — fully
interchangeable in general. The one place this bites: **multi-line `if...then...else...endif`**
is only recognized as multi-line if a real EOL token immediately follows `then`
(`ubasic.c`: `"CR after then -> multiline IF-Statement"`). A script authored as one long
semicolon-joined string with no actual line breaks (e.g. embedded as a C string literal) will
silently parse `if (...) then <next-thing>` as a *single-line* if instead, leaving a following
`else`/`endif` as syntax errors — caught and printed via `serial_write` (wire that to something
real, e.g. `printk()`, or these errors are invisible). A script written as a genuine multi-line
text file (real newlines) doesn't have this problem at all. Relevant for a future syntax
checker: a naive checker operating on already-flattened/minified script text could reintroduce
exactly this ambiguity.

#ifndef GDBSERVER_TEST_FIRMWARE_H
#define GDBSERVER_TEST_FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

#define GDBSERVER_TEST_FIRMWARE_MAGIC       0x47444253UL
#define GDBSERVER_TEST_FIRMWARE_ABI_VERSION 1UL

/*
 * Host/target mailbox protocol
 * ============================
 *
 * gdbserver_test_firmware_mailbox is a fixed-layout, volatile RAM region shared
 * by this firmware and the host-side gdbserver E2E runner. It is deliberately
 * not a production IPC mechanism: it is a deterministic test control plane that
 * lets a debugger request one observable target action and inspect the result.
 * The Python FixtureMailboxClient decodes the same little-endian 440-byte layout.
 * The offset assertions below are therefore part of the test ABI. Change the ABI
 * version and its host decoder together if this structure ever changes.
 *
 * Initialization and readiness:
 * - Startup first clears magic and abi_version, initializes every other member,
 *   then publishes abi_version and finally magic ("GDBS") with DMB barriers.
 * - A host must treat the structure as usable only when both values match these
 *   constants. This prevents retained RAM after a reset from being mistaken for
 *   a newly initialized firmware instance.
 * - boot_epoch is retained independently and advances on each valid reset. It
 *   distinguishes a newly initialized mailbox from the prior boot's contents.
 *
 * Request and completion transaction:
 * 1. With the target stopped at its recurring synchronization site, the host
 *    writes command_argument, then command, then a new command_sequence last.
 *    Writing the sequence last makes it the request commit record.
 * 2. The target loop compares command_sequence with completed_sequence. A
 *    difference means exactly one request is pending. The host must not publish
 *    another request until the previous sequence is complete.
 * 3. The target sets result to IN_PROGRESS and command_state to EXECUTING, runs
 *    the command, then writes completed_sequence, result COMPLETE, and
 *    command_state COMPLETE in that order.
 * 4. The host accepts completion only when completed_sequence equals the exact
 *    sequence it issued. For commands that stop or reset the core, tests use the
 *    command-specific observable state rather than assuming ordinary completion.
 *
 * The fields are volatile because an external debugger writes and reads them.
 * This protocol has one host writer and one target reader/writer; it does not
 * support concurrent host writers or a partially published command payload.
 */

/*
 * Mailbox command reference
 *
 * Command 0: NONE
 * No target action. Firmware uses this value after initialization. The dispatcher
 * ignores it, so command_sequence and completed_sequence remain equal until the
 * host commits a real request.
 *
 * Command 1: RTT_WRITE
 * Produces one `RTT:<sequence>:<checksum>` frame on RTT up channel 0. The target
 * increments rtt_sequence before the write, rtt_messages after the write, and
 * adds any unwritten bytes to rtt_dropped_bytes. This tests normal RTT discovery,
 * output forwarding, and loss accounting.
 *
 * Command 2: ITM_WRITE
 * Asks the selected target platform to configure its CoreSight trace registers
 * for asynchronous SWO and ITM port 0, then emits one
 * `ITM:<sequence>:<checksum>` frame. itm_sequence and itm_messages prove
 * target-side output; host tests decode the same frame from pyOCD's raw SWV
 * socket.
 *
 * Command 3: SEMIHOSTING_WRITE
 * Executes SYS_WRITE0 using the Arm semihosting BKPT 0xAB convention. pyOCD must
 * recognize and service the stop, resume the target, and forward the fixed text
 * to its telnet console. semihosting_console_calls counts completed attempts.
 *
 * Command 4: LITERAL_BKPT
 * Executes ordinary BKPT #0, after incrementing literal_bkpt_calls. Unlike
 * BKPT 0xAB, this is not semihosting: GDB must receive an ordinary breakpoint
 * stop and be able to continue execution afterwards.
 *
 * Command 5: WFI
 * Saves the current interrupt-enable and sleep-control state, disables unrelated
 * NVIC sources, and enables a target-selected interrupt as the sole known wake
 * source. It records WAITING and ENTERED states around WFI. The host pends the
 * mailbox-reported interrupt, after which the firmware restores the saved state
 * and records RESUMED and wfi_wake_count.
 *
 * Command 6: HARDFAULT
 * Increments hardfault_calls, disables UsageFault handling, and executes UDF #0.
 * The resulting undefined instruction escalates to HardFault. The function never
 * returns, which lets vector-catch and fault reporting tests observe a real stop.
 *
 * Command 7: SYSTEM_RESET
 * Increments system_reset_calls and asks the selected target platform to reset.
 * Reset abandons the current request instead of acknowledging it. Startup
 * republishes a fresh mailbox and advances boot_epoch, which is the test's
 * reset-completion proof.
 *
 * Command 8: SPIN
 * Sets spin_state to RUNNING and repeatedly performs deterministic arithmetic
 * while incrementing spin_iterations. It exits only when the host writes this
 * request's exact command_sequence into spin_release_sequence, then records
 * RELEASED and the final arithmetic value in step_result.
 *
 * Command 9: STEP
 * Calls the no-inline gdbserver_test_firmware_step_sequence function with
 * command_argument and stores the result in step_result. Its non-trivial body
 * gives single-step tests a stable function entry and a visible computation.
 *
 * Command 10: RTT_BURST
 * Uses command_argument as a frame count, capped at 32. Each numbered frame is
 * sent through RTT up channel 1, which uses no-block-skip mode. The burst-specific
 * counters show whether a faster producer caused bytes to be dropped.
 *
 * Command 11: SEMIHOSTING_FILE_WRITE
 * Runs the complete GDB File-I/O sequence: SYS_OPEN, SYS_WRITE, SYS_CLOSE, then
 * SYS_ERRNO. The mailbox saves each target return value. This covers normal GDB
 * syscall replies, the error when no client can reply, and disconnect recovery.
 *
 * Command 12: WATCHPOINT_READ
 * Performs a volatile load from watchpoint_value and increments watchpoint_reads.
 * A debugger can place a DWT read watchpoint at that address and verify that the
 * server stops at the actual target memory access.
 *
 * Command 13: WATCHPOINT_WRITE
 * Stores a fixed value to watchpoint_value without a preceding target load, then
 * increments watchpoint_writes. A debugger can place a DWT write watchpoint at
 * that address and distinguish this store from the read command above.
 *
 * Command 14: RAM_EXECUTE
 * Treats the host-writable 256-byte ram_window as a Thumb function and branches
 * to it with bit zero set. Tests first write a known-safe instruction sequence,
 * then use this command to validate executable RAM and software breakpoint paths.
 *
 * Command 15: BREAKPOINT_CATALOG
 * Calls 24 different no-inline functions, each containing a NOP. Tests install
 * hardware breakpoints across these independent addresses to measure comparator
 * exhaustion, rejection of one extra breakpoint, and recovery after removal.
 *
 * Command 16: TRANSPORT_STREAM_RTT
 * Emits a bounded, low-rate sequence of `RTTS` frames through RTT channel 0.
 * transport_stream_sequence advances before each frame; RTT message and dropped
 * byte counters verify that every requested frame was accepted by the transport.
 * After frames 16 and 32 it waits for phase-release values command_sequence and
 * command_sequence + 1 in spin_release_sequence, respectively. These gates make
 * no-client/connect/disconnect transitions deterministic rather than time-based.
 *
 * Command 17: TRANSPORT_STREAM_SEMIHOSTING
 * Emits the same bounded sequence as `SEMS` frames through SYS_WRITE0. The
 * semihosting message and failure counters prove each request was attempted and
 * report any target-side non-zero semihosting result.
 *
 * Command 18: TRANSPORT_STREAM_BOTH
 * Emits each numbered frame over RTT and semihosting in the same loop iteration.
 * The shared sequence permits direct comparison of both host streams while the
 * separate counters prove neither service starved, lost, or duplicated a frame.
 */

typedef enum gdbserver_test_firmware_command {
  GDBSERVER_TEST_FIRMWARE_COMMAND_NONE = 0,
  GDBSERVER_TEST_FIRMWARE_COMMAND_RTT_WRITE = 1,
  GDBSERVER_TEST_FIRMWARE_COMMAND_ITM_WRITE = 2,
  GDBSERVER_TEST_FIRMWARE_COMMAND_SEMIHOSTING_WRITE = 3,
  GDBSERVER_TEST_FIRMWARE_COMMAND_LITERAL_BKPT = 4,
  GDBSERVER_TEST_FIRMWARE_COMMAND_WFI = 5,
  GDBSERVER_TEST_FIRMWARE_COMMAND_HARDFAULT = 6,
  GDBSERVER_TEST_FIRMWARE_COMMAND_SYSTEM_RESET = 7,
  GDBSERVER_TEST_FIRMWARE_COMMAND_SPIN = 8,
  GDBSERVER_TEST_FIRMWARE_COMMAND_STEP = 9,
  GDBSERVER_TEST_FIRMWARE_COMMAND_RTT_BURST = 10,
  GDBSERVER_TEST_FIRMWARE_COMMAND_SEMIHOSTING_FILE_WRITE = 11,
  GDBSERVER_TEST_FIRMWARE_COMMAND_WATCHPOINT_READ = 12,
  GDBSERVER_TEST_FIRMWARE_COMMAND_WATCHPOINT_WRITE = 13,
  GDBSERVER_TEST_FIRMWARE_COMMAND_RAM_EXECUTE = 14,
  GDBSERVER_TEST_FIRMWARE_COMMAND_BREAKPOINT_CATALOG = 15,
  GDBSERVER_TEST_FIRMWARE_COMMAND_TRANSPORT_STREAM_RTT = 16,
  GDBSERVER_TEST_FIRMWARE_COMMAND_TRANSPORT_STREAM_SEMIHOSTING = 17,
  GDBSERVER_TEST_FIRMWARE_COMMAND_TRANSPORT_STREAM_BOTH = 18,
} gdbserver_test_firmware_command_t;

typedef enum gdbserver_test_firmware_result {
  GDBSERVER_TEST_FIRMWARE_RESULT_IDLE = 0,
  GDBSERVER_TEST_FIRMWARE_RESULT_IN_PROGRESS = 1,
  GDBSERVER_TEST_FIRMWARE_RESULT_COMPLETE = 2,
} gdbserver_test_firmware_result_t;

typedef enum gdbserver_test_firmware_command_state {
  GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_IDLE = 0,
  GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_EXECUTING = 1,
  GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_WAITING = 2,
  GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_COMPLETE = 3,
} gdbserver_test_firmware_command_state_t;

typedef enum gdbserver_test_firmware_spin_state {
  GDBSERVER_TEST_FIRMWARE_SPIN_STATE_IDLE = 0,
  GDBSERVER_TEST_FIRMWARE_SPIN_STATE_RUNNING = 1,
  GDBSERVER_TEST_FIRMWARE_SPIN_STATE_RELEASED = 2,
} gdbserver_test_firmware_spin_state_t;

typedef enum gdbserver_test_firmware_wfi_state {
  GDBSERVER_TEST_FIRMWARE_WFI_STATE_IDLE = 0,
  GDBSERVER_TEST_FIRMWARE_WFI_STATE_PREPARED = 1,
  GDBSERVER_TEST_FIRMWARE_WFI_STATE_ENTERED = 2,
  GDBSERVER_TEST_FIRMWARE_WFI_STATE_RESUMED = 3,
} gdbserver_test_firmware_wfi_state_t;

/*
 * Mailbox field reference
 *
 * Identity and liveness:
 * - magic and abi_version are the readiness commit. Both must match before any
 *   other member is trusted.
 * - boot_epoch identifies the current initialization after a system reset.
 * - heartbeat and loop_count advance in the ordinary main loop. loop_count is
 *   also touched by breakpoint_site without changing its final value.
 *
 * Command transaction:
 * - command and command_argument are payload written by the host.
 * - command_sequence is the host-written request commit; completed_sequence is
 *   its target-written acknowledgement.
 * - result is IDLE, IN_PROGRESS, or COMPLETE. command_state offers the more
 *   detailed IDLE, EXECUTING, WAITING, or COMPLETE lifecycle. WAITING is used
 *   by WFI and SPIN while they await an external host action.
 *
 * RTT and ITM observations:
 * - rtt_messages/rtt_sequence/rtt_dropped_bytes describe primary RTT channel-0
 *   frames; rtt_input_bytes describes host-to-target RTT data and
 *   rtt_input_checksum is its order-sensitive, incrementally updated FNV-1a hash.
 * - rtt_burst_messages/rtt_burst_sequence/rtt_burst_dropped_bytes separately
 *   describe the non-blocking RTT channel-1 burst path.
 * - itm_messages/itm_sequence describe framed ITM port-0 output.
 *
 * Semihosting observations:
 * - semihosting_console_calls counts fixed SYS_WRITE0 console attempts.
 * - semihosting_file_calls counts SYS_OPEN, SYS_WRITE, and SYS_CLOSE attempts.
 * - semihosting_open_result, semihosting_write_remaining,
 *   semihosting_close_result, and semihosting_errno preserve the last File-I/O
 *   result values as raw uint32_t representations of signed semihosting values.
 *
 * Stop, reset, and memory-operation observations:
 * - literal_bkpt_calls is written before the ordinary BKPT #0 instruction.
 * - wfi_calls/wfi_state/wfi_wake_count/wfi_wake_irq describe controlled WFI
 *   entry and the target-selected interrupt used to wake it.
 * - hardfault_calls and system_reset_calls are written immediately before their
 *   respective non-returning actions.
 * - spin_iterations and spin_state expose the long-running SPIN command.
 *   spin_release_sequence carries the sequence-specific SPIN release and the two
 *   deterministic phase releases documented for transport-stream commands.
 * - step_result records STEP or SPIN arithmetic; watchpoint_value plus
 *   watchpoint_reads/watchpoint_writes expose exact data-watchpoint accesses.
 * - ram_window is 256 bytes of initialized RAM that a host may read, write, or
 *   populate with a known-safe Thumb instruction sequence for RAM_EXECUTE.
 *
 * Continuous transport observations:
 * - transport_stream_sequence advances once per requested frame before either
 *   transport emits it.
 * - transport_stream_rtt_messages/transport_stream_rtt_dropped_bytes and
 *   transport_stream_semihosting_messages/transport_stream_semihosting_failures
 *   account independently for the two outputs. Their final values prove that
 *   all requested frames completed, not merely that a final frame was observed.
 */

/* Fixed 440-byte host/target ABI. See the protocol above before changing fields. */
typedef struct gdbserver_test_firmware_mailbox {
  uint32_t magic;
  uint32_t abi_version;
  uint32_t boot_epoch;
  uint32_t heartbeat;
  uint32_t loop_count;
  uint32_t command;
  uint32_t command_sequence;
  uint32_t completed_sequence;
  uint32_t result;
  uint32_t command_argument;
  uint32_t command_state;
  uint32_t rtt_messages;
  uint32_t rtt_sequence;
  uint32_t rtt_input_bytes;
  uint32_t rtt_input_checksum;
  uint32_t rtt_dropped_bytes;
  uint32_t rtt_burst_messages;
  uint32_t rtt_burst_sequence;
  uint32_t rtt_burst_dropped_bytes;
  uint32_t itm_messages;
  uint32_t itm_sequence;
  uint32_t semihosting_console_calls;
  uint32_t semihosting_file_calls;
  uint32_t semihosting_open_result;
  uint32_t semihosting_write_remaining;
  uint32_t semihosting_close_result;
  uint32_t semihosting_errno;
  uint32_t literal_bkpt_calls;
  uint32_t wfi_calls;
  uint32_t wfi_state;
  uint32_t wfi_wake_count;
  uint32_t wfi_wake_irq;
  uint32_t hardfault_calls;
  uint32_t system_reset_calls;
  uint32_t spin_iterations;
  uint32_t spin_state;
  uint32_t spin_release_sequence;
  uint32_t step_result;
  uint32_t watchpoint_value;
  uint32_t watchpoint_reads;
  uint32_t watchpoint_writes;
  uint32_t transport_stream_sequence;
  uint32_t transport_stream_rtt_messages;
  uint32_t transport_stream_rtt_dropped_bytes;
  uint32_t transport_stream_semihosting_messages;
  uint32_t transport_stream_semihosting_failures;
  uint8_t ram_window[256];
} gdbserver_test_firmware_mailbox_t;

_Static_assert(sizeof(gdbserver_test_firmware_mailbox_t) == 440U,
               "gdbserver test firmware mailbox ABI size changed");
_Static_assert(offsetof(gdbserver_test_firmware_mailbox_t, command) == 20U,
               "gdbserver test firmware command offset changed");
_Static_assert(offsetof(gdbserver_test_firmware_mailbox_t, command_sequence) == 24U,
               "gdbserver test firmware command sequence offset changed");
_Static_assert(offsetof(gdbserver_test_firmware_mailbox_t, spin_release_sequence) == 144U,
               "gdbserver test firmware spin release offset changed");
_Static_assert(offsetof(gdbserver_test_firmware_mailbox_t, watchpoint_value) == 152U,
               "gdbserver test firmware watchpoint offset changed");
_Static_assert(offsetof(gdbserver_test_firmware_mailbox_t, transport_stream_sequence) == 164U,
               "gdbserver test firmware stream sequence offset changed");
_Static_assert(offsetof(gdbserver_test_firmware_mailbox_t, ram_window) == 184U,
               "gdbserver test firmware RAM window offset changed");

/* The volatile RAM mailbox used by the host-side E2E runner. */
extern volatile gdbserver_test_firmware_mailbox_t gdbserver_test_firmware_mailbox;
/* Read-only patterned flash used for memory-read and flash-write protocol tests. */
extern const uint8_t gdbserver_test_firmware_flash_window[256];
/* Six fixed Thumb NOPs used as the executable flash range-step interval. */
extern const uint8_t gdbserver_test_firmware_range_step_code[12];

/* Generic test-firmware entry called by the target's board-generated main function. */
int app_main(void);
/* No-inline recurring loop marker used as a stable command-synchronization breakpoint. */
void gdbserver_test_firmware_breakpoint_site(void);
/* No-inline marker reached only after a command's completion fields are published. */
void gdbserver_test_firmware_command_completion_site(void);
/* Twenty-four distinct no-inline NOP sites used by hardware-breakpoint capacity tests. */
void gdbserver_test_firmware_breakpoint_catalog_00(void);
void gdbserver_test_firmware_breakpoint_catalog_01(void);
void gdbserver_test_firmware_breakpoint_catalog_02(void);
void gdbserver_test_firmware_breakpoint_catalog_03(void);
void gdbserver_test_firmware_breakpoint_catalog_04(void);
void gdbserver_test_firmware_breakpoint_catalog_05(void);
void gdbserver_test_firmware_breakpoint_catalog_06(void);
void gdbserver_test_firmware_breakpoint_catalog_07(void);
void gdbserver_test_firmware_breakpoint_catalog_08(void);
void gdbserver_test_firmware_breakpoint_catalog_09(void);
void gdbserver_test_firmware_breakpoint_catalog_10(void);
void gdbserver_test_firmware_breakpoint_catalog_11(void);
void gdbserver_test_firmware_breakpoint_catalog_12(void);
void gdbserver_test_firmware_breakpoint_catalog_13(void);
void gdbserver_test_firmware_breakpoint_catalog_14(void);
void gdbserver_test_firmware_breakpoint_catalog_15(void);
void gdbserver_test_firmware_breakpoint_catalog_16(void);
void gdbserver_test_firmware_breakpoint_catalog_17(void);
void gdbserver_test_firmware_breakpoint_catalog_18(void);
void gdbserver_test_firmware_breakpoint_catalog_19(void);
void gdbserver_test_firmware_breakpoint_catalog_20(void);
void gdbserver_test_firmware_breakpoint_catalog_21(void);
void gdbserver_test_firmware_breakpoint_catalog_22(void);
void gdbserver_test_firmware_breakpoint_catalog_23(void);
/* Deterministic no-inline arithmetic used to verify a single Thumb instruction step. */
uint32_t gdbserver_test_firmware_step_sequence(uint32_t value);
/* Execute an ordinary BKPT #0 and increment literal_bkpt_calls before stopping. */
void gdbserver_test_firmware_literal_bkpt(void);
/* Write one caller-provided message to RTT channel 0 and update its counters. */
void gdbserver_test_firmware_rtt_write(const char *message);
/* Emit up to 32 framed messages to the non-blocking RTT burst channel. */
void gdbserver_test_firmware_rtt_burst(uint32_t count);
/* Ask the selected target platform to configure ITM/SWO and write one port-0 message. */
void gdbserver_test_firmware_itm_write(const char *message);
/* Issue the fixed SYS_WRITE0 console request and record that it was attempted. */
void gdbserver_test_firmware_semihosting_write(void);
/* Exercise the ordered SYS_OPEN, SYS_WRITE, SYS_CLOSE, and SYS_ERRNO File-I/O path. */
void gdbserver_test_firmware_semihosting_file_write(void);
/* Enter WFI until the host pends the target-reported wake interrupt. */
void gdbserver_test_firmware_wait_for_interrupt(void);
/* Force a non-returning HardFault with the count recorded before the fault. */
void gdbserver_test_firmware_trigger_hardfault(void);
/* Request a non-returning system reset with the count recorded before reset. */
void gdbserver_test_firmware_system_reset(void);

#endif

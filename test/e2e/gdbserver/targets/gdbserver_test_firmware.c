#include "gdbserver_test_firmware.h"
#include "gdbserver_test_firmware_platform.h"
#include "SEGGER_RTT.h"

#include <stdint.h>

#define GDBSERVER_TEST_FIRMWARE_RTT_BURST_BUFFER_SIZE 2048U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_OPEN     0x01U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_CLOSE    0x02U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE0   0x04U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE    0x05U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_ERRNO    0x13U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_MODE_WB  5U
#define GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR      0xA5A5A5A5UL
#define GDBSERVER_TEST_FIRMWARE_RTT_INPUT_HASH_OFFSET 2166136261UL
#define GDBSERVER_TEST_FIRMWARE_RTT_INPUT_HASH_PRIME  16777619UL
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_MAX_MESSAGES 128U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_INTERVAL_MS  20U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_PHASE_MESSAGES 16U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_RTT                0x01U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_SEMIHOSTING        0x02U

typedef void (*gdbserver_test_firmware_breakpoint_catalog_function_t)(void);

static char gdbserver_test_firmware_rtt_burst_buffer[GDBSERVER_TEST_FIRMWARE_RTT_BURST_BUFFER_SIZE];

volatile gdbserver_test_firmware_mailbox_t gdbserver_test_firmware_mailbox;

static volatile uint32_t gdbserver_test_firmware_semihosting_arguments[3]
  __attribute__((aligned(4)));

const uint8_t gdbserver_test_firmware_flash_window[256] __attribute__((used)) = {
  0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
  0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
};

/* Six Thumb NOPs stored in executable flash for target-independent range stepping. */
const uint8_t gdbserver_test_firmware_range_step_code[12]
  __attribute__((used, aligned(2))) = {
  0x00U, 0xBFU, 0x00U, 0xBFU, 0x00U, 0xBFU,
  0x00U, 0xBFU, 0x00U, 0xBFU, 0x00U, 0xBFU,
};

static const char gdbserver_test_firmware_semihosting_message[] =
  "pyOCD semihosting test firmware message\n";
static const char gdbserver_test_firmware_semihosting_filename[] =
  "gdbserver_test_firmware.bin";
static const char gdbserver_test_firmware_semihosting_file_message[] =
  "pyOCD GDB file-I/O test firmware\n";

static void gdbserver_test_firmware_initialize(void);
static void gdbserver_test_firmware_process_command(void);
static void gdbserver_test_firmware_emit_rtt_frame(void);
static void gdbserver_test_firmware_emit_rtt_burst_frame(void);
static void gdbserver_test_firmware_emit_itm_frame(void);
static void gdbserver_test_firmware_transport_stream(uint32_t count, uint32_t transports);
static void gdbserver_test_firmware_wait_for_transport_release(uint32_t release_sequence);
static void gdbserver_test_firmware_emit_transport_rtt_frame(uint32_t sequence);
static void gdbserver_test_firmware_emit_transport_semihosting_frame(uint32_t sequence);
static void gdbserver_test_firmware_rtt_poll_down(void);
static void gdbserver_test_firmware_rtt_write_to_channel(uint32_t channel, const char *message);
static unsigned gdbserver_test_firmware_string_length(const char *message);
static void gdbserver_test_firmware_write_hex(char *destination, uint32_t value);
static int32_t gdbserver_test_firmware_semihosting_call(uint32_t operation, const volatile void *argument);
static int32_t gdbserver_test_firmware_file_call(uint32_t operation, const volatile void *argument);
static void gdbserver_test_firmware_spin(uint32_t sequence);
static void gdbserver_test_firmware_watchpoint_read(void);
static void gdbserver_test_firmware_watchpoint_write(void);
static void gdbserver_test_firmware_execute_ram_window(void);
static void gdbserver_test_firmware_run_breakpoint_catalog(void);

/*
 * Initialize the test ABI, publish the initial RTT frame, then repeatedly poll
 * RTT input, expose a debugger synchronization point, and consume one mailbox
 * request. The loop deliberately has no idle delay so ordinary execution and
 * debugger run-state transitions are immediately observable through heartbeat.
 */
int app_main(void)
{
  gdbserver_test_firmware_initialize();
  gdbserver_test_firmware_emit_rtt_frame();

  for (;;) {
    gdbserver_test_firmware_mailbox.heartbeat++;
    gdbserver_test_firmware_mailbox.loop_count++;
    gdbserver_test_firmware_rtt_poll_down();
    gdbserver_test_firmware_breakpoint_site();
    gdbserver_test_firmware_process_command();
  }
}

/*
 * Provide a stable, non-inlined function entry for host breakpoints. The volatile
 * read/write keeps a real instruction sequence without changing loop_count.
 */
void __attribute__((noinline)) gdbserver_test_firmware_breakpoint_site(void)
{
  volatile uint32_t marker = gdbserver_test_firmware_mailbox.loop_count;

  marker += 1U;
  gdbserver_test_firmware_mailbox.loop_count = marker - 1U;
}

/*
 * Provide a stable, non-inlined stop point after process_command has published
 * every normal completion field. This distinguishes transport delivery from the
 * later dispatcher completion bookkeeping.
 */
void __attribute__((noinline)) gdbserver_test_firmware_command_completion_site(void)
{
  volatile uint32_t marker = gdbserver_test_firmware_mailbox.completed_sequence;

  marker += 1U;
  gdbserver_test_firmware_mailbox.completed_sequence = marker - 1U;
}

/* Generate independent function entries so each hardware breakpoint consumes one comparator. */
#define GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(index) \
  void __attribute__((noinline)) gdbserver_test_firmware_breakpoint_catalog_##index(void) \
  { \
    __asm volatile ("nop"); \
  }

GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(00)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(01)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(02)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(03)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(04)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(05)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(06)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(07)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(08)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(09)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(10)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(11)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(12)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(13)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(14)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(15)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(16)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(17)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(18)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(19)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(20)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(21)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(22)
GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(23)

#undef GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE

static const gdbserver_test_firmware_breakpoint_catalog_function_t
  gdbserver_test_firmware_breakpoint_catalog[] = {
    gdbserver_test_firmware_breakpoint_catalog_00,
    gdbserver_test_firmware_breakpoint_catalog_01,
    gdbserver_test_firmware_breakpoint_catalog_02,
    gdbserver_test_firmware_breakpoint_catalog_03,
    gdbserver_test_firmware_breakpoint_catalog_04,
    gdbserver_test_firmware_breakpoint_catalog_05,
    gdbserver_test_firmware_breakpoint_catalog_06,
    gdbserver_test_firmware_breakpoint_catalog_07,
    gdbserver_test_firmware_breakpoint_catalog_08,
    gdbserver_test_firmware_breakpoint_catalog_09,
    gdbserver_test_firmware_breakpoint_catalog_10,
    gdbserver_test_firmware_breakpoint_catalog_11,
    gdbserver_test_firmware_breakpoint_catalog_12,
    gdbserver_test_firmware_breakpoint_catalog_13,
    gdbserver_test_firmware_breakpoint_catalog_14,
    gdbserver_test_firmware_breakpoint_catalog_15,
    gdbserver_test_firmware_breakpoint_catalog_16,
    gdbserver_test_firmware_breakpoint_catalog_17,
    gdbserver_test_firmware_breakpoint_catalog_18,
    gdbserver_test_firmware_breakpoint_catalog_19,
    gdbserver_test_firmware_breakpoint_catalog_20,
    gdbserver_test_firmware_breakpoint_catalog_21,
    gdbserver_test_firmware_breakpoint_catalog_22,
    gdbserver_test_firmware_breakpoint_catalog_23,
  };

/*
 * Transform value through several data-dependent operations. Its no-inline body
 * gives single-step scenarios a predictable function entry and observable result.
 */
uint32_t __attribute__((noinline)) gdbserver_test_firmware_step_sequence(uint32_t value)
{
  value ^= 0xA5A5A5A5UL;
  value += 0x10203040UL;
  value = (value << 3U) | (value >> 29U);
  return value;
}

/* Execute a non-semihosting breakpoint and record the attempt before it stops. */
void gdbserver_test_firmware_literal_bkpt(void)
{
  gdbserver_test_firmware_mailbox.literal_bkpt_calls++;
  __asm volatile ("bkpt #0");
}

/* Write one NUL-terminated message through the primary pyOCD RTT channel. */
void gdbserver_test_firmware_rtt_write(const char *message)
{
  gdbserver_test_firmware_rtt_write_to_channel(0U, message);
}

/*
 * Write a NUL-terminated RTT message on channel 0 or 1 and account separately
 * for normal and burst traffic, including bytes rejected by the RTT buffer.
 */
static void gdbserver_test_firmware_rtt_write_to_channel(uint32_t channel, const char *message)
{
  unsigned message_length = gdbserver_test_firmware_string_length(message);
  unsigned written = SEGGER_RTT_Write(channel, message, message_length);

  if (channel == 0U) {
    gdbserver_test_firmware_mailbox.rtt_messages++;
    gdbserver_test_firmware_mailbox.rtt_dropped_bytes += message_length - written;
  } else {
    gdbserver_test_firmware_mailbox.rtt_burst_messages++;
    gdbserver_test_firmware_mailbox.rtt_burst_dropped_bytes += message_length - written;
  }
}

/* Emit at most 32 channel-1 frames so high-rate RTT tests cannot run unbounded. */
void gdbserver_test_firmware_rtt_burst(uint32_t count)
{
  if (count > 32U) {
    count = 32U;
  }
  for (uint32_t index = 0U; index < count; index++) {
    gdbserver_test_firmware_emit_rtt_burst_frame();
  }
}

/*
 * Ask the selected target platform to configure its SWO path and write one
 * NUL-terminated ITM message. No counter is incremented when the platform
 * reports that ITM output is unavailable.
 */
void gdbserver_test_firmware_itm_write(const char *message)
{
  if (gdbserver_test_firmware_platform_itm_write(message) != 0) {
    gdbserver_test_firmware_mailbox.itm_messages++;
  }
}

/* Issue the fixed SYS_WRITE0 request used by telnet console forwarding tests. */
void gdbserver_test_firmware_semihosting_write(void)
{
  (void)gdbserver_test_firmware_semihosting_call(
    GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE0,
    gdbserver_test_firmware_semihosting_message);
  gdbserver_test_firmware_mailbox.semihosting_console_calls++;
}

/*
 * Exercise a complete GDB File-I/O transaction. Every return value is retained
 * in the mailbox so tests can distinguish open, write, close, and errno failures.
 */
void gdbserver_test_firmware_semihosting_file_write(void)
{
  int32_t file_descriptor;

  gdbserver_test_firmware_mailbox.semihosting_open_result = 0U;
  gdbserver_test_firmware_mailbox.semihosting_write_remaining = 0U;
  gdbserver_test_firmware_mailbox.semihosting_close_result = 0U;
  gdbserver_test_firmware_mailbox.semihosting_errno = 0U;

  gdbserver_test_firmware_semihosting_arguments[0] =
    (uint32_t)(uintptr_t)gdbserver_test_firmware_semihosting_filename;
  gdbserver_test_firmware_semihosting_arguments[1] = GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_MODE_WB;
  gdbserver_test_firmware_semihosting_arguments[2] =
    sizeof(gdbserver_test_firmware_semihosting_filename) - 1U;
  file_descriptor = gdbserver_test_firmware_file_call(
    GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_OPEN,
    gdbserver_test_firmware_semihosting_arguments);
  gdbserver_test_firmware_mailbox.semihosting_open_result = (uint32_t)file_descriptor;

  if (file_descriptor >= 0) {
    gdbserver_test_firmware_semihosting_arguments[0] = (uint32_t)file_descriptor;
    gdbserver_test_firmware_semihosting_arguments[1] =
      (uint32_t)(uintptr_t)gdbserver_test_firmware_semihosting_file_message;
    gdbserver_test_firmware_semihosting_arguments[2] =
      sizeof(gdbserver_test_firmware_semihosting_file_message) - 1U;
    gdbserver_test_firmware_mailbox.semihosting_write_remaining = (uint32_t)gdbserver_test_firmware_file_call(
      GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE,
      gdbserver_test_firmware_semihosting_arguments);

    gdbserver_test_firmware_semihosting_arguments[0] = (uint32_t)file_descriptor;
    gdbserver_test_firmware_mailbox.semihosting_close_result = (uint32_t)gdbserver_test_firmware_file_call(
      GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_CLOSE,
      gdbserver_test_firmware_semihosting_arguments);
  }

  gdbserver_test_firmware_mailbox.semihosting_errno = (uint32_t)gdbserver_test_firmware_semihosting_call(
    GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_ERRNO,
    0);
}

/*
 * Enter the controlled WFI state provided by the selected target platform.
 * The platform preserves and restores its interrupt and sleep-control state;
 * this generic layer publishes the portable mailbox lifecycle around it.
 */
void gdbserver_test_firmware_wait_for_interrupt(void)
{
  gdbserver_test_firmware_mailbox.wfi_calls++;
  gdbserver_test_firmware_mailbox.wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_PREPARED;
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_WAITING;

  gdbserver_test_firmware_platform_wait_for_interrupt(&gdbserver_test_firmware_mailbox);
  gdbserver_test_firmware_mailbox.wfi_wake_count++;
  gdbserver_test_firmware_mailbox.wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_RESUMED;
}

/* Count and delegate a non-returning deliberate fault to the target platform. */
void gdbserver_test_firmware_trigger_hardfault(void)
{
  gdbserver_test_firmware_mailbox.hardfault_calls++;
  gdbserver_test_firmware_platform_trigger_hardfault();
  for (;;) {
  }
}

/* Count and delegate a non-returning system reset to the target platform. */
void gdbserver_test_firmware_system_reset(void)
{
  gdbserver_test_firmware_mailbox.system_reset_calls++;
  gdbserver_test_firmware_platform_system_reset();
  for (;;) {
  }
}

/*
 * Reset all mailbox fields, configure the RTT control block, and publish the
 * ready signature last. The two DMB barriers ensure the host cannot observe a
 * valid magic value before the associated ABI and payload are initialized.
 */
static void gdbserver_test_firmware_initialize(void)
{
  /*
   * A software reset can retain this RAM. Invalidate the ready signature
   * before changing the payload, then publish it only after initialization.
   */
  gdbserver_test_firmware_mailbox.magic = 0U;
  gdbserver_test_firmware_mailbox.abi_version = 0U;
  SEGGER_RTT_Init();
  (void)SEGGER_RTT_SetNameUpBuffer(0U, "pyocd");
  (void)SEGGER_RTT_SetNameDownBuffer(0U, "commands");
  (void)SEGGER_RTT_ConfigUpBuffer(1U, "burst", gdbserver_test_firmware_rtt_burst_buffer,
                                  sizeof(gdbserver_test_firmware_rtt_burst_buffer),
                                  SEGGER_RTT_MODE_NO_BLOCK_SKIP);
  gdbserver_test_firmware_mailbox.boot_epoch = gdbserver_test_firmware_platform_next_boot_epoch();
  gdbserver_test_firmware_mailbox.heartbeat = 0U;
  gdbserver_test_firmware_mailbox.loop_count = 0U;
  gdbserver_test_firmware_mailbox.command = GDBSERVER_TEST_FIRMWARE_COMMAND_NONE;
  gdbserver_test_firmware_mailbox.command_sequence = 0U;
  gdbserver_test_firmware_mailbox.completed_sequence = 0U;
  gdbserver_test_firmware_mailbox.result = GDBSERVER_TEST_FIRMWARE_RESULT_IDLE;
  gdbserver_test_firmware_mailbox.command_argument = 0U;
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_IDLE;
  gdbserver_test_firmware_mailbox.rtt_messages = 0U;
  gdbserver_test_firmware_mailbox.rtt_sequence = 0U;
  gdbserver_test_firmware_mailbox.rtt_input_bytes = 0U;
  gdbserver_test_firmware_mailbox.rtt_input_checksum = 0U;
  gdbserver_test_firmware_mailbox.rtt_dropped_bytes = 0U;
  gdbserver_test_firmware_mailbox.rtt_burst_messages = 0U;
  gdbserver_test_firmware_mailbox.rtt_burst_sequence = 0U;
  gdbserver_test_firmware_mailbox.rtt_burst_dropped_bytes = 0U;
  gdbserver_test_firmware_mailbox.itm_messages = 0U;
  gdbserver_test_firmware_mailbox.itm_sequence = 0U;
  gdbserver_test_firmware_mailbox.semihosting_console_calls = 0U;
  gdbserver_test_firmware_mailbox.semihosting_file_calls = 0U;
  gdbserver_test_firmware_mailbox.semihosting_open_result = 0U;
  gdbserver_test_firmware_mailbox.semihosting_write_remaining = 0U;
  gdbserver_test_firmware_mailbox.semihosting_close_result = 0U;
  gdbserver_test_firmware_mailbox.semihosting_errno = 0U;
  gdbserver_test_firmware_mailbox.literal_bkpt_calls = 0U;
  gdbserver_test_firmware_mailbox.wfi_calls = 0U;
  gdbserver_test_firmware_mailbox.wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_IDLE;
  gdbserver_test_firmware_mailbox.wfi_wake_count = 0U;
  gdbserver_test_firmware_mailbox.wfi_wake_irq =
    gdbserver_test_firmware_platform_wfi_wake_irq();
  gdbserver_test_firmware_mailbox.hardfault_calls = 0U;
  gdbserver_test_firmware_mailbox.system_reset_calls = 0U;
  gdbserver_test_firmware_mailbox.spin_iterations = 0U;
  gdbserver_test_firmware_mailbox.spin_state = GDBSERVER_TEST_FIRMWARE_SPIN_STATE_IDLE;
  gdbserver_test_firmware_mailbox.spin_release_sequence = 0U;
  gdbserver_test_firmware_mailbox.step_result = 0U;
  gdbserver_test_firmware_mailbox.watchpoint_value = 0x11223344UL;
  gdbserver_test_firmware_mailbox.watchpoint_reads = 0U;
  gdbserver_test_firmware_mailbox.watchpoint_writes = 0U;
  gdbserver_test_firmware_mailbox.transport_stream_sequence = 0U;
  gdbserver_test_firmware_mailbox.transport_stream_rtt_messages = 0U;
  gdbserver_test_firmware_mailbox.transport_stream_rtt_dropped_bytes = 0U;
  gdbserver_test_firmware_mailbox.transport_stream_semihosting_messages = 0U;
  gdbserver_test_firmware_mailbox.transport_stream_semihosting_failures = 0U;

  for (uint32_t index = 0U; index < sizeof(gdbserver_test_firmware_mailbox.ram_window); index++) {
    gdbserver_test_firmware_mailbox.ram_window[index] = (uint8_t)index;
  }

  /* magic is the final readiness commit observed by the host. */
  gdbserver_test_firmware_platform_memory_barrier();
  gdbserver_test_firmware_mailbox.abi_version = GDBSERVER_TEST_FIRMWARE_ABI_VERSION;
  gdbserver_test_firmware_platform_memory_barrier();
  gdbserver_test_firmware_mailbox.magic = GDBSERVER_TEST_FIRMWARE_MAGIC;
}

/*
 * Consume the one request whose sequence differs from completed_sequence.
 * Normal commands publish completion only after their complete handler returns;
 * fault and reset commands intentionally do not return to this code.
 */
static void gdbserver_test_firmware_process_command(void)
{
  uint32_t command_sequence = gdbserver_test_firmware_mailbox.command_sequence;

  if (command_sequence == gdbserver_test_firmware_mailbox.completed_sequence) {
    return;
  }

  gdbserver_test_firmware_mailbox.result = GDBSERVER_TEST_FIRMWARE_RESULT_IN_PROGRESS;
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_EXECUTING;

  switch ((gdbserver_test_firmware_command_t)gdbserver_test_firmware_mailbox.command) {
    case GDBSERVER_TEST_FIRMWARE_COMMAND_RTT_WRITE:
      gdbserver_test_firmware_emit_rtt_frame();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_ITM_WRITE:
      gdbserver_test_firmware_emit_itm_frame();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_SEMIHOSTING_WRITE:
      gdbserver_test_firmware_semihosting_write();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_LITERAL_BKPT:
      gdbserver_test_firmware_literal_bkpt();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_WFI:
      gdbserver_test_firmware_wait_for_interrupt();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_HARDFAULT:
      gdbserver_test_firmware_trigger_hardfault();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_SYSTEM_RESET:
      gdbserver_test_firmware_system_reset();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_SPIN:
      gdbserver_test_firmware_spin(command_sequence);
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_STEP:
      gdbserver_test_firmware_mailbox.step_result = gdbserver_test_firmware_step_sequence(
        gdbserver_test_firmware_mailbox.command_argument);
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_RTT_BURST:
      gdbserver_test_firmware_rtt_burst(gdbserver_test_firmware_mailbox.command_argument);
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_SEMIHOSTING_FILE_WRITE:
      gdbserver_test_firmware_semihosting_file_write();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_WATCHPOINT_READ:
      gdbserver_test_firmware_watchpoint_read();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_WATCHPOINT_WRITE:
      gdbserver_test_firmware_watchpoint_write();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_RAM_EXECUTE:
      gdbserver_test_firmware_execute_ram_window();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_BREAKPOINT_CATALOG:
      gdbserver_test_firmware_run_breakpoint_catalog();
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_TRANSPORT_STREAM_RTT:
      gdbserver_test_firmware_transport_stream(
        gdbserver_test_firmware_mailbox.command_argument,
        GDBSERVER_TEST_FIRMWARE_TRANSPORT_RTT);
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_TRANSPORT_STREAM_SEMIHOSTING:
      gdbserver_test_firmware_transport_stream(
        gdbserver_test_firmware_mailbox.command_argument,
        GDBSERVER_TEST_FIRMWARE_TRANSPORT_SEMIHOSTING);
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_TRANSPORT_STREAM_BOTH:
      gdbserver_test_firmware_transport_stream(
        gdbserver_test_firmware_mailbox.command_argument,
        GDBSERVER_TEST_FIRMWARE_TRANSPORT_RTT |
        GDBSERVER_TEST_FIRMWARE_TRANSPORT_SEMIHOSTING);
      break;

    case GDBSERVER_TEST_FIRMWARE_COMMAND_NONE:
    default:
      break;
  }

  gdbserver_test_firmware_mailbox.completed_sequence = command_sequence;
  gdbserver_test_firmware_mailbox.result = GDBSERVER_TEST_FIRMWARE_RESULT_COMPLETE;
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_COMPLETE;
  gdbserver_test_firmware_command_completion_site();
}


/* Format and emit the next primary RTT frame with its sequence-derived checksum. */
static void gdbserver_test_firmware_emit_rtt_frame(void)
{
  char frame[] = "RTT:00000000:00000000\n";
  uint32_t sequence = gdbserver_test_firmware_mailbox.rtt_sequence + 1U;

  gdbserver_test_firmware_mailbox.rtt_sequence = sequence;
  gdbserver_test_firmware_write_hex(&frame[4], sequence);
  gdbserver_test_firmware_write_hex(&frame[13], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  gdbserver_test_firmware_rtt_write(frame);
}

/* Format and emit the next channel-1 RTT burst frame with a separate counter. */
static void gdbserver_test_firmware_emit_rtt_burst_frame(void)
{
  char frame[] = "RTTB:00000000:00000000\n";
  uint32_t sequence = gdbserver_test_firmware_mailbox.rtt_burst_sequence + 1U;

  gdbserver_test_firmware_mailbox.rtt_burst_sequence = sequence;
  gdbserver_test_firmware_write_hex(&frame[5], sequence);
  gdbserver_test_firmware_write_hex(&frame[14], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  gdbserver_test_firmware_rtt_write_to_channel(1U, frame);
}

/* Format and emit the next port-0 ITM frame with its sequence-derived checksum. */
static void gdbserver_test_firmware_emit_itm_frame(void)
{
  char frame[] = "ITM:00000000:00000000\n";
  uint32_t sequence = gdbserver_test_firmware_mailbox.itm_sequence + 1U;

  gdbserver_test_firmware_mailbox.itm_sequence = sequence;
  gdbserver_test_firmware_write_hex(&frame[4], sequence);
  gdbserver_test_firmware_write_hex(&frame[13], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  gdbserver_test_firmware_itm_write(frame);
}

/*
 * Emit a bounded, low-rate numbered stream on one or both requested transports.
 * Sequence is advanced before each emit so a host can observe progress while the
 * command is running. Deterministic release gates after frames 16 and 32 let the
 * host change debugger-client state without racing the target producer. Command
 * completion is published only after the final emit.
 */
static void gdbserver_test_firmware_transport_stream(uint32_t count, uint32_t transports)
{
  if (count == 0U || count > GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_MAX_MESSAGES) {
    count = GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_MAX_MESSAGES;
  }

  for (uint32_t index = 0U; index < count; index++) {
    uint32_t sequence = gdbserver_test_firmware_mailbox.transport_stream_sequence + 1U;

    gdbserver_test_firmware_mailbox.transport_stream_sequence = sequence;
    if ((transports & GDBSERVER_TEST_FIRMWARE_TRANSPORT_RTT) != 0U) {
      gdbserver_test_firmware_emit_transport_rtt_frame(sequence);
    }
    if ((transports & GDBSERVER_TEST_FIRMWARE_TRANSPORT_SEMIHOSTING) != 0U) {
      gdbserver_test_firmware_emit_transport_semihosting_frame(sequence);
    }
    gdbserver_test_firmware_platform_delay(
      GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_INTERVAL_MS);
    if ((index + 1U) == GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_PHASE_MESSAGES) {
      gdbserver_test_firmware_wait_for_transport_release(
        gdbserver_test_firmware_mailbox.command_sequence);
    } else if ((index + 1U) == (2U * GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_PHASE_MESSAGES)) {
      gdbserver_test_firmware_wait_for_transport_release(
        gdbserver_test_firmware_mailbox.command_sequence + 1U);
    }
  }
}

/* Wait at a deterministic stream phase boundary until the host releases it. */
static void gdbserver_test_firmware_wait_for_transport_release(uint32_t release_sequence)
{
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_WAITING;
  while (gdbserver_test_firmware_mailbox.spin_release_sequence != release_sequence) {
  }
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_EXECUTING;
}

/* Emit one stream frame on RTT and record both attempted messages and lost bytes. */
static void gdbserver_test_firmware_emit_transport_rtt_frame(uint32_t sequence)
{
  char frame[] = "RTTS:00000000:00000000\n";
  unsigned message_length = sizeof(frame) - 1U;
  unsigned written;

  gdbserver_test_firmware_write_hex(&frame[5], sequence);
  gdbserver_test_firmware_write_hex(&frame[14], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  written = SEGGER_RTT_Write(0U, frame, message_length);
  gdbserver_test_firmware_mailbox.transport_stream_rtt_messages++;
  gdbserver_test_firmware_mailbox.transport_stream_rtt_dropped_bytes += message_length - written;
}

/* Emit one stream frame through SYS_WRITE0 and record every non-zero return as a failure. */
static void gdbserver_test_firmware_emit_transport_semihosting_frame(uint32_t sequence)
{
  char frame[] = "SEMS:00000000:00000000\n";
  int32_t result;

  gdbserver_test_firmware_write_hex(&frame[5], sequence);
  gdbserver_test_firmware_write_hex(&frame[14], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  result = gdbserver_test_firmware_semihosting_call(
    GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE0, frame);
  gdbserver_test_firmware_mailbox.transport_stream_semihosting_messages++;
  if (result != 0) {
    gdbserver_test_firmware_mailbox.transport_stream_semihosting_failures++;
  }
}

/*
 * Drain all currently queued RTT down-channel input, accumulate its byte count
 * and order-sensitive FNV-1a checksum, and acknowledge it with a primary frame.
 */
static void gdbserver_test_firmware_rtt_poll_down(void)
{
  uint8_t input[64];
  uint32_t input_bytes = 0U;
  uint32_t input_checksum = gdbserver_test_firmware_mailbox.rtt_input_checksum;
  unsigned bytes_read;

  do {
    bytes_read = SEGGER_RTT_Read(0U, input, sizeof(input));
    for (unsigned index = 0U; index < bytes_read; index++) {
      if (input_bytes == 0U && gdbserver_test_firmware_mailbox.rtt_input_bytes == 0U) {
        input_checksum = GDBSERVER_TEST_FIRMWARE_RTT_INPUT_HASH_OFFSET;
      }
      input_bytes++;
      input_checksum ^= input[index];
      input_checksum *= GDBSERVER_TEST_FIRMWARE_RTT_INPUT_HASH_PRIME;
    }
  } while (bytes_read == sizeof(input));

  if (input_bytes != 0U) {
    gdbserver_test_firmware_mailbox.rtt_input_bytes += input_bytes;
    gdbserver_test_firmware_mailbox.rtt_input_checksum = input_checksum;
    gdbserver_test_firmware_emit_rtt_frame();
  }
}

/* Return the byte count of a NUL-terminated message without using a C library. */
static unsigned gdbserver_test_firmware_string_length(const char *message)
{
  unsigned length = 0U;

  while (message[length] != '\0') {
    length++;
  }

  return length;
}

/* Write exactly eight upper-case hexadecimal digits, most significant digit first. */
static void gdbserver_test_firmware_write_hex(char *destination, uint32_t value)
{
  static const char digits[] = "0123456789ABCDEF";

  for (uint32_t index = 0U; index < 8U; index++) {
    destination[7U - index] = digits[value & 0xFU];
    value >>= 4U;
  }
}

/*
 * Execute the Arm semihosting calling convention: operation in r0, argument in
 * r1, BKPT 0xAB, then the signed target result returned in r0. The memory clobber
 * prevents request argument accesses from moving across the debugger-visible stop.
 */
static int32_t gdbserver_test_firmware_semihosting_call(uint32_t operation, const volatile void *argument)
{
  uint32_t result;

  __asm volatile (
    "mov r0, %1\n"
    "mov r1, %2\n"
    "bkpt 0xAB\n"
    "mov %0, r0\n"
    : "=&r"(result)
    : "r"(operation), "r"(argument)
    : "r0", "r1", "memory");
  return (int32_t)result;
}

/* Count one File-I/O operation before issuing its underlying semihosting request. */
static int32_t gdbserver_test_firmware_file_call(uint32_t operation, const volatile void *argument)
{
  gdbserver_test_firmware_mailbox.semihosting_file_calls++;
  return gdbserver_test_firmware_semihosting_call(operation, argument);
}

/*
 * Remain in an observable running state until the host writes the exact request
 * sequence to spin_release_sequence. The arithmetic and iteration count provide
 * proof of target progress without peripheral dependencies.
 */
static void gdbserver_test_firmware_spin(uint32_t sequence)
{
  uint32_t value = 0U;

  gdbserver_test_firmware_mailbox.spin_state = GDBSERVER_TEST_FIRMWARE_SPIN_STATE_RUNNING;
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_WAITING;
  while (gdbserver_test_firmware_mailbox.spin_release_sequence != sequence) {
    value = gdbserver_test_firmware_step_sequence(value + gdbserver_test_firmware_mailbox.spin_iterations);
    gdbserver_test_firmware_mailbox.spin_iterations++;
  }
  gdbserver_test_firmware_mailbox.spin_state = GDBSERVER_TEST_FIRMWARE_SPIN_STATE_RELEASED;
  gdbserver_test_firmware_mailbox.step_result = value;
}

/* Perform one volatile read of watchpoint_value for a hardware read-watchpoint test. */
static void gdbserver_test_firmware_watchpoint_read(void)
{
  volatile uint32_t value = gdbserver_test_firmware_mailbox.watchpoint_value;

  (void)value;
  gdbserver_test_firmware_mailbox.watchpoint_reads++;
}

/* Perform one store-only access to watchpoint_value for write-watchpoint tests. */
static void gdbserver_test_firmware_watchpoint_write(void)
{
  gdbserver_test_firmware_mailbox.watchpoint_value = 0x55667788UL;
  gdbserver_test_firmware_mailbox.watchpoint_writes++;
}

/* Branch to the host-populated RAM window as Thumb code; callers must provide safe bytes. */
static void gdbserver_test_firmware_execute_ram_window(void)
{
  typedef void (*gdbserver_test_firmware_ram_function_t)(void);
  gdbserver_test_firmware_ram_function_t function = (gdbserver_test_firmware_ram_function_t)
    ((uintptr_t)gdbserver_test_firmware_mailbox.ram_window | 1U);

  function();
}

/* Call every catalog function in order, exercising all installed breakpoint slots. */
static void gdbserver_test_firmware_run_breakpoint_catalog(void)
{
  for (uint32_t index = 0U;
       index < (sizeof(gdbserver_test_firmware_breakpoint_catalog) /
                sizeof(gdbserver_test_firmware_breakpoint_catalog[0]));
       index++) {
    gdbserver_test_firmware_breakpoint_catalog[index]();
  }
}

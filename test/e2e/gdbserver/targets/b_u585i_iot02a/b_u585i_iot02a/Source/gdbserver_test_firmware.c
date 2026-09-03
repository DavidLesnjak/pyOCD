#include "main.h"
#include "gdbserver_test_firmware.h"
#include "SEGGER_RTT.h"

#include <stdint.h>

#define GDBSERVER_TEST_FIRMWARE_RTT_BURST_BUFFER_SIZE 2048U
#define GDBSERVER_TEST_FIRMWARE_ITM_PORT             0U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_OPEN     0x01U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_CLOSE    0x02U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE0   0x04U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE    0x05U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_ERRNO    0x13U
#define GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_MODE_WB  5U
#define GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC       0x5245544EUL
#define GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR      0xA5A5A5A5UL
#define GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT      4U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_MAX_MESSAGES 128U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_INTERVAL_MS  20U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_RTT                0x01U
#define GDBSERVER_TEST_FIRMWARE_TRANSPORT_SEMIHOSTING        0x02U

#define GDBSERVER_TEST_FIRMWARE_DEMCR      (*(volatile uint32_t *)0xE000EDFCUL)
#define GDBSERVER_TEST_FIRMWARE_DWT_CTRL   (*(volatile uint32_t *)0xE0001000UL)
#define GDBSERVER_TEST_FIRMWARE_DWT_CYCCNT (*(volatile uint32_t *)0xE0001004UL)
#define GDBSERVER_TEST_FIRMWARE_ITM_STIM0  (*(volatile uint32_t *)0xE0000000UL)
#define GDBSERVER_TEST_FIRMWARE_ITM_TER    (*(volatile uint32_t *)0xE0000E00UL)
#define GDBSERVER_TEST_FIRMWARE_ITM_TPR    (*(volatile uint32_t *)0xE0000E40UL)
#define GDBSERVER_TEST_FIRMWARE_ITM_TCR    (*(volatile uint32_t *)0xE0000E80UL)
#define GDBSERVER_TEST_FIRMWARE_ITM_LAR    (*(volatile uint32_t *)0xE0000FB0UL)
#define GDBSERVER_TEST_FIRMWARE_TPI_ACPR   (*(volatile uint32_t *)0xE0040010UL)
#define GDBSERVER_TEST_FIRMWARE_TPI_SPPR   (*(volatile uint32_t *)0xE00400F0UL)

typedef struct gdbserver_test_firmware_retained_state {
  uint32_t magic;
  uint32_t magic_inverse;
  uint32_t boot_epoch;
  uint32_t boot_epoch_inverse;
} gdbserver_test_firmware_retained_state_t;

typedef struct gdbserver_test_firmware_wfi_snapshot {
  uint32_t iser[GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT];
  uint32_t scr;
} gdbserver_test_firmware_wfi_snapshot_t;

typedef void (*gdbserver_test_firmware_breakpoint_catalog_function_t)(void);

static char gdbserver_test_firmware_rtt_burst_buffer[GDBSERVER_TEST_FIRMWARE_RTT_BURST_BUFFER_SIZE];

volatile gdbserver_test_firmware_mailbox_t gdbserver_test_firmware_mailbox;

static volatile gdbserver_test_firmware_retained_state_t gdbserver_test_firmware_retained_state
  __attribute__((section(".bss.noinit"), used, aligned(8)));
static gdbserver_test_firmware_wfi_snapshot_t gdbserver_test_firmware_wfi_snapshot;
static volatile uint32_t gdbserver_test_firmware_semihosting_arguments[3]
  __attribute__((aligned(4)));

const uint8_t gdbserver_test_firmware_flash_window[256] __attribute__((used)) = {
  0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
  0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
};

static const char gdbserver_test_firmware_semihosting_message[] =
  "pyOCD semihosting test firmware message\n";
static const char gdbserver_test_firmware_semihosting_filename[] =
  "gdbserver_test_firmware.bin";
static const char gdbserver_test_firmware_semihosting_file_message[] =
  "pyOCD GDB file-I/O test firmware\n";

static void gdbserver_test_firmware_initialize(void);
static uint32_t gdbserver_test_firmware_next_boot_epoch(void);
static void gdbserver_test_firmware_process_command(void);
static void gdbserver_test_firmware_configure_itm(void);
static void gdbserver_test_firmware_emit_rtt_frame(void);
static void gdbserver_test_firmware_emit_rtt_burst_frame(void);
static void gdbserver_test_firmware_emit_itm_frame(void);
static void gdbserver_test_firmware_transport_stream(uint32_t count, uint32_t transports);
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

void __attribute__((noinline)) gdbserver_test_firmware_breakpoint_site(void)
{
  volatile uint32_t marker = gdbserver_test_firmware_mailbox.loop_count;

  marker += 1U;
  gdbserver_test_firmware_mailbox.loop_count = marker - 1U;
}

#define GDBSERVER_TEST_FIRMWARE_DEFINE_BREAKPOINT_CATALOG_SITE(index) \
  void __attribute__((noinline)) gdbserver_test_firmware_breakpoint_catalog_##index(void) \
  { \
    __NOP(); \
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

uint32_t __attribute__((noinline)) gdbserver_test_firmware_step_sequence(uint32_t value)
{
  value ^= 0xA5A5A5A5UL;
  value += 0x10203040UL;
  value = (value << 3U) | (value >> 29U);
  return value;
}

void gdbserver_test_firmware_literal_bkpt(void)
{
  gdbserver_test_firmware_mailbox.literal_bkpt_calls++;
  __BKPT(0);
}

void gdbserver_test_firmware_rtt_write(const char *message)
{
  gdbserver_test_firmware_rtt_write_to_channel(0U, message);
}

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

void gdbserver_test_firmware_rtt_burst(uint32_t count)
{
  if (count > 32U) {
    count = 32U;
  }
  for (uint32_t index = 0U; index < count; index++) {
    gdbserver_test_firmware_emit_rtt_burst_frame();
  }
}

void gdbserver_test_firmware_itm_write(const char *message)
{
  gdbserver_test_firmware_configure_itm();

  if ((GDBSERVER_TEST_FIRMWARE_ITM_TCR & 1U) == 0U ||
      (GDBSERVER_TEST_FIRMWARE_ITM_TER & (1UL << GDBSERVER_TEST_FIRMWARE_ITM_PORT)) == 0U) {
    return;
  }

  while (*message != '\0') {
    while ((GDBSERVER_TEST_FIRMWARE_ITM_STIM0 & 1U) == 0U) {
    }

    *((volatile uint8_t *)0xE0000000UL) = (uint8_t)*message;
    message++;
  }

  gdbserver_test_firmware_mailbox.itm_messages++;
}

void gdbserver_test_firmware_semihosting_write(void)
{
  (void)gdbserver_test_firmware_semihosting_call(
    GDBSERVER_TEST_FIRMWARE_SEMIHOSTING_WRITE0,
    gdbserver_test_firmware_semihosting_message);
  gdbserver_test_firmware_mailbox.semihosting_console_calls++;
}

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

void gdbserver_test_firmware_wait_for_interrupt(void)
{
  gdbserver_test_firmware_mailbox.wfi_calls++;
  gdbserver_test_firmware_mailbox.wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_PREPARED;
  gdbserver_test_firmware_mailbox.command_state = GDBSERVER_TEST_FIRMWARE_COMMAND_STATE_WAITING;

  for (uint32_t index = 0U; index < GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT; index++) {
    gdbserver_test_firmware_wfi_snapshot.iser[index] = NVIC->ISER[index];
    NVIC->ICER[index] = 0xFFFFFFFFUL;
    NVIC->ICPR[index] = 0xFFFFFFFFUL;
  }
  gdbserver_test_firmware_wfi_snapshot.scr = SCB->SCR;
  HAL_SuspendTick();
  NVIC_ClearPendingIRQ(TIM17_IRQn);
  NVIC_EnableIRQ(TIM17_IRQn);
  SCB->SCR &= ~(SCB_SCR_SLEEPDEEP_Msk | SCB_SCR_SLEEPONEXIT_Msk | SCB_SCR_SEVONPEND_Msk);
  gdbserver_test_firmware_mailbox.wfi_wake_irq = (uint32_t)TIM17_IRQn;
  gdbserver_test_firmware_mailbox.wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_ENTERED;
  __DSB();
  __WFI();
  __ISB();

  NVIC_ClearPendingIRQ(TIM17_IRQn);
  for (uint32_t index = 0U; index < GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT; index++) {
    NVIC->ICER[index] = 0xFFFFFFFFUL;
    NVIC->ICPR[index] = 0xFFFFFFFFUL;
    NVIC->ISER[index] = gdbserver_test_firmware_wfi_snapshot.iser[index];
  }
  SCB->SCR = gdbserver_test_firmware_wfi_snapshot.scr;
  HAL_ResumeTick();
  gdbserver_test_firmware_mailbox.wfi_wake_count++;
  gdbserver_test_firmware_mailbox.wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_RESUMED;
}

void gdbserver_test_firmware_trigger_hardfault(void)
{
  gdbserver_test_firmware_mailbox.hardfault_calls++;
  SCB->SHCSR &= ~SCB_SHCSR_USGFAULTENA_Msk;
  __DSB();
  __asm volatile ("udf #0");
  for (;;) {
  }
}

void gdbserver_test_firmware_system_reset(void)
{
  gdbserver_test_firmware_mailbox.system_reset_calls++;
  __DSB();
  NVIC_SystemReset();
  for (;;) {
  }
}

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
  gdbserver_test_firmware_mailbox.boot_epoch = gdbserver_test_firmware_next_boot_epoch();
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
  gdbserver_test_firmware_mailbox.wfi_wake_irq = (uint32_t)TIM17_IRQn;
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
  __DMB();
  gdbserver_test_firmware_mailbox.abi_version = GDBSERVER_TEST_FIRMWARE_ABI_VERSION;
  __DMB();
  gdbserver_test_firmware_mailbox.magic = GDBSERVER_TEST_FIRMWARE_MAGIC;
}

static uint32_t gdbserver_test_firmware_next_boot_epoch(void)
{
  uint32_t boot_epoch;

  if (gdbserver_test_firmware_retained_state.magic != GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC ||
      gdbserver_test_firmware_retained_state.magic_inverse != ~GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC ||
      gdbserver_test_firmware_retained_state.boot_epoch_inverse !=
        ~gdbserver_test_firmware_retained_state.boot_epoch) {
    boot_epoch = 0U;
  } else {
    boot_epoch = gdbserver_test_firmware_retained_state.boot_epoch;
  }

  boot_epoch++;
  gdbserver_test_firmware_retained_state.magic = 0U;
  gdbserver_test_firmware_retained_state.magic_inverse = ~0U;
  gdbserver_test_firmware_retained_state.boot_epoch = boot_epoch;
  gdbserver_test_firmware_retained_state.boot_epoch_inverse = ~boot_epoch;
  gdbserver_test_firmware_retained_state.magic_inverse = ~GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC;
  gdbserver_test_firmware_retained_state.magic = GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC;
  return boot_epoch;
}

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
}

static void gdbserver_test_firmware_configure_itm(void)
{
  GDBSERVER_TEST_FIRMWARE_DEMCR |= (1UL << 24U);
  GDBSERVER_TEST_FIRMWARE_DWT_CYCCNT = 0U;
  GDBSERVER_TEST_FIRMWARE_DWT_CTRL |= 1U;
  GDBSERVER_TEST_FIRMWARE_ITM_LAR = 0xC5ACCE55UL;
  GDBSERVER_TEST_FIRMWARE_TPI_ACPR = 79U;
  GDBSERVER_TEST_FIRMWARE_TPI_SPPR = 2U;
  GDBSERVER_TEST_FIRMWARE_ITM_TPR = 0U;
  GDBSERVER_TEST_FIRMWARE_ITM_TER = (1UL << GDBSERVER_TEST_FIRMWARE_ITM_PORT);
  GDBSERVER_TEST_FIRMWARE_ITM_TCR = 0x0001000DUL;
}

static void gdbserver_test_firmware_emit_rtt_frame(void)
{
  char frame[] = "RTT:00000000:00000000\n";
  uint32_t sequence = gdbserver_test_firmware_mailbox.rtt_sequence + 1U;

  gdbserver_test_firmware_mailbox.rtt_sequence = sequence;
  gdbserver_test_firmware_write_hex(&frame[4], sequence);
  gdbserver_test_firmware_write_hex(&frame[13], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  gdbserver_test_firmware_rtt_write(frame);
}

static void gdbserver_test_firmware_emit_rtt_burst_frame(void)
{
  char frame[] = "RTTB:00000000:00000000\n";
  uint32_t sequence = gdbserver_test_firmware_mailbox.rtt_burst_sequence + 1U;

  gdbserver_test_firmware_mailbox.rtt_burst_sequence = sequence;
  gdbserver_test_firmware_write_hex(&frame[5], sequence);
  gdbserver_test_firmware_write_hex(&frame[14], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  gdbserver_test_firmware_rtt_write_to_channel(1U, frame);
}

static void gdbserver_test_firmware_emit_itm_frame(void)
{
  char frame[] = "ITM:00000000:00000000\n";
  uint32_t sequence = gdbserver_test_firmware_mailbox.itm_sequence + 1U;

  gdbserver_test_firmware_mailbox.itm_sequence = sequence;
  gdbserver_test_firmware_write_hex(&frame[4], sequence);
  gdbserver_test_firmware_write_hex(&frame[13], sequence ^ GDBSERVER_TEST_FIRMWARE_FRAME_CHECK_XOR);
  gdbserver_test_firmware_itm_write(frame);
}

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
    HAL_Delay(GDBSERVER_TEST_FIRMWARE_TRANSPORT_STREAM_INTERVAL_MS);
  }
}

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

static void gdbserver_test_firmware_rtt_poll_down(void)
{
  uint8_t input[64];
  uint32_t input_bytes = 0U;
  uint32_t input_checksum = 0U;
  unsigned bytes_read;

  do {
    bytes_read = SEGGER_RTT_Read(0U, input, sizeof(input));
    for (unsigned index = 0U; index < bytes_read; index++) {
      input_bytes++;
      input_checksum += input[index];
    }
  } while (bytes_read == sizeof(input));

  if (input_bytes != 0U) {
    gdbserver_test_firmware_mailbox.rtt_input_bytes += input_bytes;
    gdbserver_test_firmware_mailbox.rtt_input_checksum += input_checksum;
    gdbserver_test_firmware_emit_rtt_frame();
  }
}

static unsigned gdbserver_test_firmware_string_length(const char *message)
{
  unsigned length = 0U;

  while (message[length] != '\0') {
    length++;
  }

  return length;
}

static void gdbserver_test_firmware_write_hex(char *destination, uint32_t value)
{
  static const char digits[] = "0123456789ABCDEF";

  for (uint32_t index = 0U; index < 8U; index++) {
    destination[7U - index] = digits[value & 0xFU];
    value >>= 4U;
  }
}

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

static int32_t gdbserver_test_firmware_file_call(uint32_t operation, const volatile void *argument)
{
  gdbserver_test_firmware_mailbox.semihosting_file_calls++;
  return gdbserver_test_firmware_semihosting_call(operation, argument);
}

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

static void gdbserver_test_firmware_watchpoint_read(void)
{
  volatile uint32_t value = gdbserver_test_firmware_mailbox.watchpoint_value;

  (void)value;
  gdbserver_test_firmware_mailbox.watchpoint_reads++;
}

static void gdbserver_test_firmware_watchpoint_write(void)
{
  gdbserver_test_firmware_mailbox.watchpoint_value++;
  gdbserver_test_firmware_mailbox.watchpoint_writes++;
}

static void gdbserver_test_firmware_execute_ram_window(void)
{
  typedef void (*gdbserver_test_firmware_ram_function_t)(void);
  gdbserver_test_firmware_ram_function_t function = (gdbserver_test_firmware_ram_function_t)
    ((uintptr_t)gdbserver_test_firmware_mailbox.ram_window | 1U);

  function();
}

static void gdbserver_test_firmware_run_breakpoint_catalog(void)
{
  for (uint32_t index = 0U;
       index < (sizeof(gdbserver_test_firmware_breakpoint_catalog) /
                sizeof(gdbserver_test_firmware_breakpoint_catalog[0]));
       index++) {
    gdbserver_test_firmware_breakpoint_catalog[index]();
  }
}

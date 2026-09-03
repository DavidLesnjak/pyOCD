#ifndef GDBSERVER_TEST_FIRMWARE_H
#define GDBSERVER_TEST_FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

#define GDBSERVER_TEST_FIRMWARE_MAGIC       0x47444253UL
#define GDBSERVER_TEST_FIRMWARE_ABI_VERSION 1UL

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

extern volatile gdbserver_test_firmware_mailbox_t gdbserver_test_firmware_mailbox;
extern const uint8_t gdbserver_test_firmware_flash_window[256];

void gdbserver_test_firmware_breakpoint_site(void);
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
uint32_t gdbserver_test_firmware_step_sequence(uint32_t value);
void gdbserver_test_firmware_literal_bkpt(void);
void gdbserver_test_firmware_rtt_write(const char *message);
void gdbserver_test_firmware_rtt_burst(uint32_t count);
void gdbserver_test_firmware_itm_write(const char *message);
void gdbserver_test_firmware_semihosting_write(void);
void gdbserver_test_firmware_semihosting_file_write(void);
void gdbserver_test_firmware_wait_for_interrupt(void);
void gdbserver_test_firmware_trigger_hardfault(void);
void gdbserver_test_firmware_system_reset(void);

#endif

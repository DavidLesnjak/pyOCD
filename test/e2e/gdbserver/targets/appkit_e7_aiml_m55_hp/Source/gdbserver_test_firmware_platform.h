/*
 * AppKit-E7-AIML M55_HP implementation of services required by the generic
 * gdbserver test firmware. This is the only target-specific interface consumed
 * by the shared firmware core in ../../gdbserver_test_firmware.c.
 */
#ifndef GDBSERVER_TEST_FIRMWARE_PLATFORM_H
#define GDBSERVER_TEST_FIRMWARE_PLATFORM_H

#include <stdint.h>

#include "gdbserver_test_firmware.h"

/* Publish a data-memory barrier before the generic core exposes mailbox readiness. */
void gdbserver_test_firmware_platform_memory_barrier(void);
/* Recover and advance the no-init reset generation for this target. */
uint32_t gdbserver_test_firmware_platform_next_boot_epoch(void);
/* Return the NVIC interrupt number selected as the controlled WFI wake source. */
uint32_t gdbserver_test_firmware_platform_wfi_wake_irq(void);
/* Configure the target's trace path and write message to ITM; return nonzero on success. */
int gdbserver_test_firmware_platform_itm_write(const char *message);
/* Enter WFI and restore the target's interrupt and sleep-control state after wake. */
void gdbserver_test_firmware_platform_wait_for_interrupt(
  volatile gdbserver_test_firmware_mailbox_t *mailbox);
/* Delay for a small bounded interval while continuous transport frames are emitted. */
void gdbserver_test_firmware_platform_delay(uint32_t milliseconds);
/* Deliberately enter a non-returning HardFault. */
void gdbserver_test_firmware_platform_trigger_hardfault(void);
/* Request a non-returning target system reset. */
void gdbserver_test_firmware_platform_system_reset(void);

#endif

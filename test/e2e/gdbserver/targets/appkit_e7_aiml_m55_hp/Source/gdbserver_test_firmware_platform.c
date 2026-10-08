#include "RTE_Components.h"
#include CMSIS_device_header

#include "gdbserver_test_firmware_platform.h"

#define GDBSERVER_TEST_FIRMWARE_ITM_PORT        0U
#define GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC  0x5245544EUL
#define GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT 15U
#define GDBSERVER_TEST_FIRMWARE_SWO_CLOCK_HZ    2000000UL

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

typedef struct gdbserver_test_firmware_platform_retained_state {
  uint32_t magic;
  uint32_t magic_inverse;
  uint32_t boot_epoch;
  uint32_t boot_epoch_inverse;
} gdbserver_test_firmware_platform_retained_state_t;

typedef struct gdbserver_test_firmware_platform_wfi_snapshot {
  uint32_t iser[GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT];
  uint32_t scr;
} gdbserver_test_firmware_platform_wfi_snapshot_t;

static volatile gdbserver_test_firmware_platform_retained_state_t
  gdbserver_test_firmware_platform_retained_state
  __attribute__((section(".bss.noinit"), used, aligned(8)));
static gdbserver_test_firmware_platform_wfi_snapshot_t
  gdbserver_test_firmware_platform_wfi_snapshot;

/* Configure asynchronous SWO for the documented 400 MHz M55_HP core clock. */
static void gdbserver_test_firmware_platform_configure_itm(void)
{
  uint32_t swo_divider = SystemCoreClock / GDBSERVER_TEST_FIRMWARE_SWO_CLOCK_HZ;

  GDBSERVER_TEST_FIRMWARE_DEMCR |= (1UL << 24U);
  GDBSERVER_TEST_FIRMWARE_DWT_CYCCNT = 0U;
  GDBSERVER_TEST_FIRMWARE_DWT_CTRL |= 1U;
  GDBSERVER_TEST_FIRMWARE_ITM_LAR = 0xC5ACCE55UL;
  GDBSERVER_TEST_FIRMWARE_TPI_ACPR = (swo_divider > 0U) ? (swo_divider - 1U) : 0U;
  GDBSERVER_TEST_FIRMWARE_TPI_SPPR = 2U;
  GDBSERVER_TEST_FIRMWARE_ITM_TPR = 0U;
  GDBSERVER_TEST_FIRMWARE_ITM_TER = (1UL << GDBSERVER_TEST_FIRMWARE_ITM_PORT);
  GDBSERVER_TEST_FIRMWARE_ITM_TCR = 0x0001000DUL;
}

/* The host pends LPTIMER3 directly; no peripheral status needs servicing. */
void LPTIMER3_IRQHandler(void)
{
}

void gdbserver_test_firmware_platform_memory_barrier(void)
{
  __DMB();
}

/* Recover a valid no-init reset record, then publish the next epoch with inverted copies. */
uint32_t gdbserver_test_firmware_platform_next_boot_epoch(void)
{
  uint32_t boot_epoch;

  if (gdbserver_test_firmware_platform_retained_state.magic !=
        GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC ||
      gdbserver_test_firmware_platform_retained_state.magic_inverse !=
        ~GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC ||
      gdbserver_test_firmware_platform_retained_state.boot_epoch_inverse !=
        ~gdbserver_test_firmware_platform_retained_state.boot_epoch) {
    boot_epoch = 0U;
  } else {
    boot_epoch = gdbserver_test_firmware_platform_retained_state.boot_epoch;
  }

  boot_epoch++;
  gdbserver_test_firmware_platform_retained_state.magic = 0U;
  gdbserver_test_firmware_platform_retained_state.magic_inverse = ~0U;
  gdbserver_test_firmware_platform_retained_state.boot_epoch = boot_epoch;
  gdbserver_test_firmware_platform_retained_state.boot_epoch_inverse = ~boot_epoch;
  gdbserver_test_firmware_platform_retained_state.magic_inverse =
    ~GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC;
  gdbserver_test_firmware_platform_retained_state.magic = GDBSERVER_TEST_FIRMWARE_RETAINED_MAGIC;
  SCB_CleanDCache_by_Addr(
    (volatile void *)&gdbserver_test_firmware_platform_retained_state,
    (int32_t)sizeof(gdbserver_test_firmware_platform_retained_state));
  __DSB();
  return boot_epoch;
}

uint32_t gdbserver_test_firmware_platform_wfi_wake_irq(void)
{
  return (uint32_t)LPTIMER3_IRQ_IRQn;
}

/* Return zero if the target cannot enable ITM port 0; otherwise write every byte. */
int gdbserver_test_firmware_platform_itm_write(const char *message)
{
  gdbserver_test_firmware_platform_configure_itm();

  if ((GDBSERVER_TEST_FIRMWARE_ITM_TCR & 1U) == 0U ||
      (GDBSERVER_TEST_FIRMWARE_ITM_TER & (1UL << GDBSERVER_TEST_FIRMWARE_ITM_PORT)) == 0U) {
    return 0;
  }

  while (*message != '\0') {
    while ((GDBSERVER_TEST_FIRMWARE_ITM_STIM0 & 1U) == 0U) {
    }

    *((volatile uint8_t *)0xE0000000UL) = (uint8_t)*message;
    message++;
  }

  return 1;
}

void gdbserver_test_firmware_platform_wait_for_interrupt(
  volatile gdbserver_test_firmware_mailbox_t *mailbox)
{
  for (uint32_t index = 0U; index < GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT; index++) {
    gdbserver_test_firmware_platform_wfi_snapshot.iser[index] = NVIC->ISER[index];
    NVIC->ICER[index] = 0xFFFFFFFFUL;
    NVIC->ICPR[index] = 0xFFFFFFFFUL;
  }
  gdbserver_test_firmware_platform_wfi_snapshot.scr = SCB->SCR;
  NVIC_ClearPendingIRQ(LPTIMER3_IRQ_IRQn);
  NVIC_EnableIRQ(LPTIMER3_IRQ_IRQn);
  SCB->SCR &= ~(SCB_SCR_SLEEPDEEP_Msk | SCB_SCR_SLEEPONEXIT_Msk | SCB_SCR_SEVONPEND_Msk);
  mailbox->wfi_wake_irq = gdbserver_test_firmware_platform_wfi_wake_irq();
  mailbox->wfi_state = GDBSERVER_TEST_FIRMWARE_WFI_STATE_ENTERED;
  __DSB();
  __WFI();
  __ISB();

  NVIC_DisableIRQ(LPTIMER3_IRQ_IRQn);
  NVIC_ClearPendingIRQ(LPTIMER3_IRQ_IRQn);
  for (uint32_t index = 0U; index < GDBSERVER_TEST_FIRMWARE_NVIC_BANK_COUNT; index++) {
    NVIC->ICER[index] = 0xFFFFFFFFUL;
    NVIC->ICPR[index] = 0xFFFFFFFFUL;
    NVIC->ISER[index] = gdbserver_test_firmware_platform_wfi_snapshot.iser[index];
  }
  SCB->SCR = gdbserver_test_firmware_platform_wfi_snapshot.scr;
}

/* Use the DWT cycle counter so stream pacing does not depend on an OS tick. */
void gdbserver_test_firmware_platform_delay(uint32_t milliseconds)
{
  uint32_t cycles_per_millisecond = SystemCoreClock / 1000U;

  GDBSERVER_TEST_FIRMWARE_DEMCR |= (1UL << 24U);
  GDBSERVER_TEST_FIRMWARE_DWT_CTRL |= 1U;
  for (uint32_t elapsed = 0U; elapsed < milliseconds; elapsed++) {
    uint32_t start = GDBSERVER_TEST_FIRMWARE_DWT_CYCCNT;

    while ((GDBSERVER_TEST_FIRMWARE_DWT_CYCCNT - start) < cycles_per_millisecond) {
    }
  }
}

void gdbserver_test_firmware_platform_trigger_hardfault(void)
{
  SCB->SHCSR &= ~SCB_SHCSR_USGFAULTENA_Msk;
  __DSB();
  __asm volatile ("udf #0");
  for (;;) {
  }
}

void gdbserver_test_firmware_platform_system_reset(void)
{
  __DSB();
  NVIC_SystemReset();
  for (;;) {
  }
}

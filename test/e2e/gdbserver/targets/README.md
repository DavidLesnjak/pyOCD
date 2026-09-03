# Test firmware targets

`gdbserver_test_firmware.c` and `.h` define the board-independent test behavior
and mailbox ABI shared by every target. Each board directory holds one flattened
CMSIS solution and a small `Source/gdbserver_test_firmware_platform.*` adapter
for services that cannot be portable, such as delay, WFI wake setup, reset,
fault injection, retained boot state, and trace output configuration.

The host runner derives the target identity and ELF path from cbuild-run. SWV
runtime clocks are intentionally not inferred from its processor `max-clock`:
each SWO-capable target must document and pass its actual system clock and SWO
baud with `--gdbserver-swv-system-clock` and `--gdbserver-swv-clock`.

Reusable scenario definitions belong in `../scenarios/`, and reusable host
runner code belongs in `../runner/`; neither belongs in an individual target
directory.

## Adding a board target

Keep the mailbox ABI and command implementation in the shared files unchanged.
The board's `.cproject.yml` must compile `../gdbserver_test_firmware.c` and its
own `Source/gdbserver_test_firmware_platform.c`, and must add both `..` and
`Source` as C include paths.

The platform adapter must provide the functions declared in its local
`gdbserver_test_firmware_platform.h`:

- a data-memory barrier and a reset-persistent boot epoch;
- the interrupt number and setup/restore sequence for controlled WFI;
- bounded delay, deliberate HardFault, and system reset services; and
- trace-path setup plus synchronous ITM port-0 output.

Select a wake interrupt that pyOCD can pend while the core is in WFI. The
adapter writes that interrupt number to `mailbox.wfi_wake_irq`; scenarios use
the published value instead of a board-specific constant. Rebuild the csolution
after any source or adapter change and pass its generated cbuild-run file to
the E2E runner.

# AppKit-E7-AIML M55_HP gdbserver hardware test firmware

This target runs the shared gdbserver E2E test firmware on the Alif Semiconductor
AppKit-E7-AIML revision D1 board. It intentionally selects only the
`AE722F80F55D5LS:M55_HP` processor; multicore and TrustZone scenarios remain
outside this target's scope.

## CMSIS identity and layout

- Board: `Alif Semiconductor::AppKit-E7-AIML:D1`
- Device and processor: `Alif Semiconductor::AE722F80F55D5LS:M55_HP`
- Support pack: `AlifSemiconductor::Ensemble@2.1.0`
- Locally copied board layer: `Board/AppKit-E7-AIML/Board_HP.clayer.yml`
- Shared firmware and mailbox ABI: `../gdbserver_test_firmware.c` and `.h`
- Target adapter: `Source/gdbserver_test_firmware_platform.c` and `.h`
- Built target description: `out/GDBServerTest+AppKit-E7-M55-HP.cbuild-run.yml`

The local board layer retains the vendor's SWD/JTAG pin configuration so TDO can
carry SWO. Its entry point omits camera, display, USB, UART, and NPU
initialization, together with the layer's redundant cache-enable call, because
those services are unrelated to gdbserver testing. The mailbox, RTT control
block, and executable RAM window are linked into the pack-declared M55_HP DTCM
so the startup-enabled data cache cannot hide target writes from the debugger or
debugger writes from the target.

The adapter uses `LPTIMER3_IRQ_IRQn` (external IRQ 63) as the controlled WFI wake
source and supplies a no-op handler because the host pends the NVIC interrupt
directly. A dedicated uninitialized SRAM region preserves `boot_epoch` across a
system reset; the adapter cleans that retained cache line after every update.
This does not change the shared mailbox ABI, which remains version 1.

## Board preparation

The Alif pack requires the device ATOC and the single-core M55_HE/M55_HP debug
stubs to be installed with Alif SETOOLS before an example can run. Follow the
installed Ensemble pack instructions and select the M55_HP single-core setup.

The test runner is probe-independent. For the external ULINKplus, connect its
CMSIS-DAP SWD signals and SWO/TDO signal to the board, then pass that probe's UID
with `--gdbserver-probe-uid`. The cbuild-run file selects M55_HP; the probe UID
selects which connected CMSIS-DAP probe pyOCD opens.

## Build and run

Build with the CMSIS environment declared by `vcpkg-configuration.json`:

```powershell
cbuild GDBServerTest.csolution.yml --context GDBServerTest.Debug+AppKit-E7-M55-HP
```

Run the target-independent scenarios from the repository root:

```powershell
$probe = '<ULINKplus CMSIS-DAP UID>'
$cbuildRun = 'test\e2e\gdbserver\targets\appkit_e7_aiml_m55_hp\out\GDBServerTest+AppKit-E7-M55-HP.cbuild-run.yml'
$gdb = 'C:\path\to\arm-none-eabi-gdb.exe'
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios --gdbserver-e2e --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun --gdbserver-gdb $gdb --gdbserver-extra-arg=--core --gdbserver-extra-arg=0 -vv
```

SWV is explicitly gated. This target configures a 400 MHz M55_HP system clock
and 2 MHz asynchronous SWO, so enable its raw-RSP SWV scenarios with:

```powershell
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios\rsp\test_swv.py --gdbserver-e2e --gdbserver-swv --gdbserver-swv-system-clock 400000000 --gdbserver-swv-clock 2000000 --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun -vv
```

Do not enable the destructive flash-protocol scenario until an Alif MRAM range
has been explicitly reserved outside the test image, ATOC, debug stubs, and all
other device data.

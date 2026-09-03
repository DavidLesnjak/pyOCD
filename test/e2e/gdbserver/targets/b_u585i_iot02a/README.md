# B-U585I-IOT02A gdbserver hardware test firmware

This target provides the first deterministic hardware test firmware for the pyOCD
gdbserver end-to-end framework. The framework and firmware do not use AI at
runtime.

## Locations

- CMSIS solution: `b_u585i_iot02a/`
- CubeMX-generated board layer: `b_u585i_iot02a/Board/B-U585I-IOT02A/`
- Test-firmware source and mailbox ABI: `b_u585i_iot02a/Source/`
- Built target description: `b_u585i_iot02a/out/CubeMX+STM32U585AIIx.cbuild-run.yml`
- Host-side scenarios and recommended execution order: [`../../scenarios/README.md`](../../scenarios/README.md)

The cbuild-run file must be regenerated after test firmware changes. It tells pyOCD
which target to use and identifies the matching AXF with symbols, so the test
runner must receive that file rather than a manually selected `--target`.

## Stream-oriented coverage

- `test_rtt.py` verifies automatic `_SEGGER_RTT` symbol discovery, an explicit
  control-block address, startup without GDB, RTT down-channel input, and both
  test firmware output channels. Channel 0 carries low-rate `RTT:` frames; channel 1
  carries high-rate `RTTB:` frames and is checked for complete, ordered output.
  The suite also drains data after halt and verifies RTT continuity across GDB,
  target-reset, and TCP-stream reconnects.
- `test_semihosting.py` distinguishes a disabled semihosting trap from enabled
  handling, captures console output through telnet, and exercises exact GDB
  File-I/O content, no-active-client, disconnect, sequence, reset, and
  reconnect paths.
- `test_swv.py` decodes test firmware port-0 ITM frames from raw SWV data only when
  the operator supplies `--gdbserver-swv` after confirming the SWO pin route
  and probe capability. It covers early and late stream attachment, no-GDB
  collection, halt/reconnect draining, consumer replacement, and deliberately
  incorrect SWO clock configuration.
- `test_flash.py` is skipped unless both flash scratch options are supplied;
  it uses only that declared reserved region and exercises escaped
  `vFlashWrite` payload bytes.

The other scenarios cover mailbox access, RSP memory and registers, software
and hardware breakpoint behavior (including hardware-comparator exhaustion),
watchpoints, execution control, reset, WFI, faults, reconnect, all-stop,
non-stop, and multiple clients. `test_gdb_client.py` is a separate optional
load-and-debug smoke case. All scenarios in `scenarios/arm_gdb/` require an
explicit `--gdbserver-gdb EXECUTABLE`.

## Capability boundaries

The selected generated board layer sets `processor.trustzone: off`. Therefore
this test firmware validates one TrustZone-disabled Cortex-M33 image only; it does
not claim secure/non-secure access coverage. The board test firmware also exposes one
application core. TrustZone and multicore scenarios are deliberately deferred;
add a separate target/layer and deterministic firmware support before treating
either area as covered.

## Running

Build the solution and use the PowerShell command in
[`../../README.md`](../../README.md). Keep the probe exclusive to this suite.
The runner writes per-test logs, RSP traffic, and side-channel captures under
`test/e2e/gdbserver/artifacts/`, which are the first place to inspect a
hardware failure. `run.json` identifies the scenario, pyOCD version and
checkout, test firmware hashes, effective options, and probe; `rsp.jsonl` labels
traffic by RSP connection.

Do not enable the flash scenario until an erase-aligned, disposable flash
sector has been reserved outside the test firmware image and board boot data.

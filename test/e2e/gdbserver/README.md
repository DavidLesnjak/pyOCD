# gdbserver end-to-end hardware tests

This directory contains deterministic hardware tests for pyOCD gdbserver. An
AI agent may help develop the framework, but neither the test firmware nor
the test execution is AI driven.

## Layout

- `runner/`: reusable raw-RSP client, mailbox driver, process control, stream
  collectors, pytest plugin, and per-run artifacts.
- `scenarios/rsp/`: reusable raw-RSP behavior tests that run against the
  common test firmware ABI and the selected target's declared capabilities.
- `scenarios/arm_gdb/`: equivalent behavior tests driven through an explicitly
  selected `arm-none-eabi-gdb` executable.
- `scenarios/README.md`: generated, execution-ordered documentation assembled
  from each scenario test's structured docstring.
- `targets/`: one board-specific test firmware implementation per physical board.
- `targets/b_u585i_iot02a/b_u585i_iot02a/`: the CMSIS csolution project for
  the B-U585I-IOT02A. This is the project location; there is no `firmware/`
  directory.
- `targets/b_u585i_iot02a/`: the first target implementation used with the
  reusable scenarios.

Each hardware test starts an isolated pyOCD gdbserver, programs the current
test firmware by default, and saves the gdbserver log, RSP packets, streams, and run
metadata below `test/e2e/gdbserver/artifacts/`.

## Build and run the B-U585I-IOT02A suite

First build the csolution using the configured CMSIS-Toolbox environment. The
generated cbuild-run file is both the target description and the source of the
AXF path used by pyOCD:

```powershell
cbuild test\e2e\gdbserver\targets\b_u585i_iot02a\b_u585i_iot02a\CubeMX.csolution.yml --context CubeMX.Debug+STM32U585AIIx
```

Set the probe UID and Arm GDB path before invoking pytest. In PowerShell, an
unset variable expands to nothing, which causes pytest to report that the
corresponding option has no argument.

```powershell
$probe = '000A00214741500320383733'
$cbuildRun = 'test\e2e\gdbserver\targets\b_u585i_iot02a\b_u585i_iot02a\out\CubeMX+STM32U585AIIx.cbuild-run.yml'
$gdb = 'C:\path\to\arm-none-eabi-gdb.exe'
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios --gdbserver-e2e --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun --gdbserver-gdb $gdb -vv
```

RTT and semihosting scenarios configure their required pyOCD options through
their `gdbserver_config` marker. Do not pass `--gdbserver-semihosting` to the
whole suite: one scenario intentionally verifies the disabled-semihosting
breakpoint behavior.

## Raw RSP and external GDB groups

Tests in `scenarios/rsp/` use the runner's raw RSP client and are marked
`gdbserver_rsp`. Tests in `scenarios/arm_gdb/` are driven by one or more real
`arm-none-eabi-gdb` processes and are marked `gdbserver_arm_gdb`. Equivalent
behaviours have the same test name in both directories, so the client used is
clear from the test path rather than an awkward name suffix.

External-GDB tests are skipped unless `--gdbserver-gdb` identifies the intended
executable; the runner never chooses a GDB installation implicitly.

Every hardware test has a structured source docstring with its purpose,
numbered execution steps, exact pass condition, and failure diagnosis. Pytest
validates that contract during collection. Regenerate the execution-ordered
scenario reference after editing a test description with:

```powershell
venv\Scripts\python.exe test\e2e\gdbserver\runner\scenario_docs.py
venv\Scripts\python.exe test\e2e\gdbserver\runner\scenario_docs.py --check
```

For example, run the standard-GDB all-stop two-client scenario with:

```powershell
$gdb = 'C:\path\to\arm-none-eabi-gdb.exe'
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios\arm_gdb\test_clients.py::test_two_clients_all_stop_can_observe_and_release_spin --gdbserver-e2e --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun --gdbserver-gdb $gdb -vv
```

Run the two transport groups independently with:

```powershell
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios\rsp --gdbserver-e2e --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun -vv
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios\arm_gdb --gdbserver-e2e --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun --gdbserver-gdb $gdb -vv
```

### Cases that cannot be implemented faithfully with arm-none-eabi-gdb

These remain raw-RSP tests because standard GDB either consumes the
relevant packet internally or cannot coordinate the required connection state.
They are intentionally not represented as skipped external-GDB test cases.

- Breakpoint capacity: `rsp/test_breakpoint_capacity.py::test_hardware_breakpoint_capacity_reports_exhaustion_and_recovers`.
  GDB does not expose the failing `Z1` reply required to prove capacity recovery.
- Flash protocol: `rsp/test_flash.py::test_vflash_programs_only_the_user_declared_scratch_region`.
  GDB can load the test firmware, but cannot constrain and inspect its internal
  `vFlash` requests to the user-declared scratch range.
- Dispatched-step client loss:
  `rsp/test_clients.py::test_server_recovers_after_dispatched_single_step_client_disconnect`.
  GDB's `stepi` is synchronous at its command interface, so a test cannot
  deliberately terminate GDB after pyOCD accepted the RSP step but before GDB
  consumes the matching stop reply.
- Asynchronous execution control:
  `rsp/test_execution.py::test_single_step_is_rejected_while_another_client_is_running`.
  GDB serializes the second step behind its own client state and hides the
  required `E01` RSP reply.
- WFI and no-client operation:
  `rsp/test_fault_sleep.py::test_wfi_wakes_from_host_pended_nvic_interrupt`,
  `rsp/test_no_client.py::test_server_runs_test_firmware_before_a_gdb_client_connects`.
  They require a host operation during execution or explicitly no client.
- Exact wire protocol: both cases in `test_protocol.py`, and
  `rsp/test_reset.py::test_extended_remote_reset_reinitializes_test_firmware`. They
  validate exact `qC`, `p`, `QStartNoAckMode`, `M`, `X`, and reply-less `R0`
  packet behavior that GDB generates or consumes itself.
- RTT initial frame:
  `rsp/test_rtt.py::test_rtt_symbol_discovery_serves_initial_frame_without_gdb_client`.
  Its required condition is that no GDB client has ever connected.
- RTT and SWV service lifecycle. The raw cases intentionally control whether a
  GDB client or stream consumer exists and inspect exact side-channel bytes:
  `rsp/test_rtt.py::test_rtt_output_is_drained_after_target_halt`,
  `rsp/test_rtt.py::test_active_rtt_stream_survives_final_gdb_disconnect_and_reconnect`,
  `rsp/test_rtt.py::test_active_rtt_stream_rediscovers_after_target_reset_and_gdb_reconnect`,
  `rsp/test_swv.py::test_swv_raw_stream_captures_itm_without_a_gdb_client`, and
  `rsp/test_swv.py::test_swv_raw_consumer_disconnects_and_reconnects`.
- Semihosting lifecycle and File-I/O. These require observing or replying to
  semihosting `F` packets, no active client, or a raw RSP reset:
  `rsp/test_semihosting.py::test_semihosting_console_handles_several_requests_in_one_run`,
  `rsp/test_semihosting.py::test_semihosting_console_is_serviced_after_final_gdb_detach`,
  `rsp/test_semihosting.py::test_semihosting_console_works_after_rsp_reset_and_reconnect`,
  `rsp/test_semihosting.py::test_gdb_file_syscalls_round_trip_to_active_client`,
  `rsp/test_semihosting.py::test_gdb_file_syscalls_complete_after_single_step`,
  `rsp/test_semihosting.py::test_gdb_file_syscalls_fail_without_an_active_client`, and
  `rsp/test_semihosting.py::test_gdb_file_syscall_recovers_when_active_client_disconnects`.
- SWV. These validate bytes from the raw SWV stream, which standard GDB does
  not consume: `rsp/test_swv.py::test_swv_raw_stream_captures_test_firmware_itm_data_with_semihosting`,
  `rsp/test_swv.py::test_swv_raw_stream_attaches_after_target_execution_begins`, and
  `rsp/test_swv.py::test_swv_raw_stream_drains_after_halt_and_controller_reconnect`,
  plus the deliberately incorrect-clock case
  `rsp/test_swv.py::test_swv_incorrect_clock_does_not_decode_a_valid_itm_frame`.

Every scenario has a separate artifact directory. Its `run.json` records the
scenario, target description and hashes, probe UID, pyOCD version and checkout,
effective session options, and process command. `rsp.jsonl` also records the
connection that produced each packet, while the corresponding stream and tool
logs preserve side-channel data.

## Explicitly gated scenarios

SWV depends on the physical SWO route and probe support. It is skipped unless
`--gdbserver-swv` is supplied, and that option should only be used after those
capabilities have been verified:

```powershell
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios\rsp\test_swv.py --gdbserver-e2e --gdbserver-swv --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun -vv
```

The flash protocol test is also skipped by default. It programs only the
address and size that the operator declares, so reserve an erase-aligned flash
region that is outside the test firmware image, boot configuration, and any user
data before enabling it:

```powershell
venv\Scripts\pytest.exe test\e2e\gdbserver\scenarios\rsp\test_flash.py --gdbserver-e2e --gdbserver-probe-uid $probe --gdbserver-cbuild-run $cbuildRun --gdbserver-flash-scratch-address 0xYOUR_RESERVED_ADDRESS --gdbserver-flash-scratch-size 0xYOUR_RESERVED_SIZE -vv
```

## Deferred target classes

The current suite deliberately covers a single Cortex-M core. TrustZone
secure/non-secure paths and multicore gdbserver behavior are deferred until a
target implementation exposes deterministic firmware entry points and explicit
capabilities for those modes. They are not counted as skipped or passing tests.

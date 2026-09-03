# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Execution-control scenarios exercised through arm-none-eabi-gdb."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_multi_client_workflow, run_single_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_software_breakpoint_executes_test_firmware_owned_ram_code(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that standard GDB can install, hit, and step over a software breakpoint
    in executable RAM without corrupting the original instruction.

    Test method:
    1. Connect Arm GDB, synchronize at the recurring breakpoint, and reserve the
       next mailbox command sequence for RAM-code execution.
    2. Write a Thumb ``BX LR`` instruction into the executable mailbox RAM window.
    3. Ask GDB to install a software breakpoint at that RAM address and submit the
       command that calls the RAM window.
    4. Continue until GDB reports the breakpoint and record the program counter.
    5. Execute one ``stepi`` and require the program counter to move away from the
       breakpoint address, proving pyOCD restored and executed the real instruction.
    6. Remove the breakpoint, continue to command completion, and detach.

    Expected result:
    GDB stops at the RAM address, one instruction step changes PC, and the firmware
    completes the command with the original RAM instruction intact.

    Failure indicates:
    Software-breakpoint patching, instruction restoration, cache synchronization,
    single-step handling, or mailbox command execution is broken.
    """
    run_single_client_workflow("software-breakpoint", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_hardware_breakpoint_stops_and_allows_execution_to_resume(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a standard GDB hardware breakpoint can be removed, reinstalled,
    hit repeatedly, and cleaned up without preventing later execution.

    Test method:
    1. Connect GDB and install a hardware breakpoint at the recurring firmware site.
    2. Continue to the first stop, record PC, and delete that breakpoint.
    3. Install a new hardware breakpoint at the same symbol and continue again.
    4. Record the second stop PC and query the register view exposed by GDB.
    5. Require both stops to name hardware-assisted breakpoints at the same non-zero
       address, then delete all breakpoints and detach.

    Expected result:
    Both independently installed hardware breakpoints stop at the same site and the
    target remains controllable after removal and reinsertion.

    Failure indicates:
    FPB programming, breakpoint cleanup/reuse, stop reporting, or resume behavior is
    inconsistent through standard GDB.
    """
    run_single_client_workflow("hardware-breakpoint", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_literal_bkpt_can_be_single_stepped_then_completes_after_continue(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a literal ``BKPT`` instruction emitted by the firmware is reported
    as a stop and can be stepped over without immediately retriggering at the same PC.

    Test method:
    1. Connect GDB, synchronize at the recurring breakpoint, and submit the literal
       BKPT mailbox command.
    2. Continue until execution reaches the instruction encoded in the firmware.
    3. Record the stopped PC before issuing any resume operation.
    4. Execute exactly one ``stepi`` and record the new PC.
    5. Require the new PC to differ from the literal breakpoint address.
    6. Continue to the mailbox completion breakpoint and verify the command sequence.

    Expected result:
    The literal breakpoint produces a visible stop, ``stepi`` advances PC, and the
    original command subsequently completes.

    Failure indicates:
    pyOCD misclassifies a literal BKPT as a managed breakpoint, re-triggers the same
    instruction, or loses the command after the stop.
    """
    run_single_client_workflow("literal-bkpt", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_single_step_from_a_known_function_entry(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify ordinary instruction stepping from a deterministic firmware function
    entry, independent of literal or installed breakpoint corner cases.

    Test method:
    1. Connect GDB and synchronize at the recurring firmware breakpoint.
    2. Submit the STEP mailbox command and install a breakpoint at
       ``gdbserver_test_firmware_step_sequence``.
    3. Continue until GDB stops at that known function entry and record PC.
    4. Execute one machine instruction with ``stepi`` and record PC again.
    5. Require the second PC to be non-zero and different from the first.
    6. Remove the temporary breakpoint, continue to mailbox completion, and detach.

    Expected result:
    GDB stops at the requested function, advances by one instruction, and the test
    firmware completes the command after execution resumes.

    Failure indicates:
    Basic single-step dispatch, stop acknowledgement, register refresh, or resume
    after stepping is broken.
    """
    run_single_client_workflow("single-step", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_single_step_over_installed_hardware_breakpoint(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify GDB's common step-over sequence when a hardware breakpoint remains
    logically installed at the current program counter.

    Test method:
    1. Connect GDB, synchronize, and submit the STEP mailbox command.
    2. Install a hardware breakpoint at the step-sequence function entry.
    3. Continue to that breakpoint and record the stopped PC.
    4. Issue ``stepi`` while GDB still owns the breakpoint at the current address.
    5. Record PC and require it to advance instead of retriggering at the same site.
    6. Delete the breakpoint, continue to command completion, and detach.

    Expected result:
    GDB and pyOCD temporarily step past the installed hardware breakpoint, report a
    new PC, and preserve normal execution afterward.

    Failure indicates:
    Breakpoint step-over, FPB comparator suspension/reinstallation, or target-state
    synchronization is broken.
    """
    run_single_client_workflow("hardware-step-over", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.parametrize(
    ("access_type", "workflow"),
    (("write", "watch-write"), ("read", "watch-read"),
     ("access-read", "watch-access-read"), ("access-write", "watch-access-write")),
    ids=("write", "read", "access-read", "access-write"))
def test_watchpoints_stop_for_each_supported_access_type(
        access_type: str,
        workflow: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that standard GDB can configure and report write, read, and access
    watchpoints on a deterministic firmware variable.

    Test method:
    1. Select the parameterized GDB command: ``watch`` for write, ``rwatch`` for
       read, or ``awatch`` for either-access behavior.
    2. Connect GDB and stop at the recurring synchronization breakpoint.
    3. Delete that breakpoint and single-step past it before making the mailbox
       command executable, so GDB has no breakpoint step-over to perform while
       the watched command runs.
    4. Submit the matching mailbox read/write command, install the watchpoint on
       ``watchpoint_value``, and continue until the firmware performs the access.
    5. Record the mailbox completion sequence and PC at the watchpoint stop, then
       require GDB's transcript to identify a watchpoint while the command is still
       incomplete.
    6. Delete the watchpoint, restore the synchronization breakpoint, continue to
       command completion, and detach.

    Expected result:
    Every parameterized access type stops at the intended memory access before the
    command completes, then allows completion after the watchpoint is removed.

    Failure indicates:
    DWT comparator programming, GDB watchpoint translation, stop-reason reporting,
    access-type matching, or the isolated watchpoint execution sequence is broken.
    """
    del access_type
    run_single_client_workflow(workflow, gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_ctrl_c_halts_a_host_released_spin_command(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a user-style Ctrl-C interrupt delivered through real GDB halts a
    running target and leaves it resumable.

    Test method:
    1. Start an asynchronous all-stop GDB/MI controller and synchronize it at the
       recurring firmware breakpoint.
    2. Connect a temporary standard GDB observer while the controller is stopped.
    3. Submit a SPIN command and continue without blocking the controller.
    4. Poll the observer's mailbox view until the
       SPIN iteration counter proves the target is physically executing, then detach
       that observer.
    5. Send GDB/MI interrupt, equivalent to Ctrl-C, from the controller and wait for
       its stop event.
    6. Write the command's release sequence, install the completion breakpoint,
       continue, and wait for that sequence to complete.

    Expected result:
    Ctrl-C stops a confirmed-running SPIN promptly, and the controller can release,
    resume, and complete the command after the temporary observer disconnects.

    Failure indicates:
    Cross-client target-state observation, host interrupt delivery, halt detection,
    GDB/MI asynchronous state, or the subsequent resume path is broken.
    """
    run_multi_client_workflow("ctrl-c", gdbserver_gdb, gdbserver_server)

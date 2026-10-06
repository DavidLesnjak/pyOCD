# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Breakpoint and semihosting sequences exercised through arm-none-eabi-gdb."""

import re
import time

import pytest

from mailbox import MailboxCommand, MailboxCommandState
from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB, ExternalGDBSession

from ._workflows import run_single_client_workflow


_CHAIN_FIRST_BKPT_OFFSET = 8
_GATED_MIXED_LOOP_START = 14
_GATED_MIXED_BKPT_OFFSET = 32
# SYS_TIME, publish WAITING, count iterations until released, BKPT 0, BX LR.
# The four LDR literals are 32-bit mailbox-field addresses at offsets 36-48.
_GATED_MIXED_INSTRUCTIONS = (
    0x2011, 0x2100, 0xbeab, 0x4a07, 0x2302, 0x6013,
    0x4a06, 0x6813, 0x3301, 0x6013, 0x4905, 0x680b,
    0x4905, 0x6809, 0x428b, 0xd1f6, 0xbe00, 0x4770,
)
_GATED_MIXED_LITERALS = (
    (36, "command_state"),
    (40, "spin_iterations"),
    (44, "spin_release_sequence"),
    (48, "command_sequence"),
)


@pytest.mark.gdbserver_external_gdb
def test_hardware_breakpoint_stops_the_test_firmware(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that Arm GDB can stop the running test firmware at a hardware breakpoint.
    Test method:
    1. Launch the explicitly selected Arm GDB with the test firmware symbols and connect by extended-remote.
    2. Insert an hbreak at the repeatedly executed test firmware breakpoint site.
    3. Continue and require GDB to report a hardware-assisted stop at that symbol and a valid PC.
    4. Remove the first breakpoint, reinstall it, and continue to the same site again to prove execution resumed.
    5. Record both stop PCs, remove all breakpoints, and detach cleanly.
    Expected result: GDB stops there and reports the program counter.
    Failure indicates: Standard GDB hardware-breakpoint interoperability is broken.
    """
    run_single_client_workflow("hardware-breakpoint", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
@pytest.mark.parametrize("sequence", ("SS", "SB", "BS", "BB", "SBS"))
def test_arm_gdb_steps_through_adjacent_semihost_and_literal_bkpts(
        sequence: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that Arm GDB can single-step each instruction in adjacent semihosting
    and literal BKPT chains without repeating or skipping an address.

    Test method:
    1. Program executable RAM with the selected S/B chain, where S is BKPT 0xAB
       and B is an ordinary BKPT 0, and start the firmware RAM command.
    2. Stop at the NOP before the chain, step to its first BKPT, and then step
       each BKPT once. Set the SYS_TIME arguments before each semihosting step.
    3. Require each stopped PC to advance by two bytes, each S to replace R0
       with its result, and each B to preserve R0.
    4. Continue to the firmware completion breakpoint and verify its sequence.

    Expected result: SS, SB, BS, BB, and SBS chains each advance one BKPT per
    GDB step and the RAM command completes.
    Failure indicates: A semihost call was missed, a literal BKPT repeated or
    was skipped, or GDB lost target control after stepping.
    """
    output = _run_adjacent_bkpt_sequence(gdbserver_gdb, gdbserver_server, sequence, step_each=True)
    base = _assert_sequence_entry(output)
    before = re.search(r"GDB-E2E chain-before=0x([0-9a-f]+) r0=(\d+)", output)
    assert before is not None, output
    assert int(before.group(1), 16) == base + _CHAIN_FIRST_BKPT_OFFSET, output
    previous_r0 = int(before.group(2))
    assert previous_r0 == 17, output

    steps = re.findall(r"GDB-E2E chain-step=(\d+) pc=0x([0-9a-f]+) r0=(\d+)", output)
    assert len(steps) == len(sequence), output
    for index, (step_number, program_counter, result) in enumerate(steps):
        assert int(step_number) == index, output
        assert int(program_counter, 16) == base + _CHAIN_FIRST_BKPT_OFFSET + (index + 1) * 2, output
        current_r0 = int(result)
        if sequence[index] == "S":
            assert current_r0 != 17, output
        else:
            assert current_r0 == previous_r0, output
        previous_r0 = current_r0

    _assert_sequence_completed(output)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
@pytest.mark.parametrize("sequence", ("SS", "SB", "BS", "BB", "SBS"))
def test_arm_gdb_continue_reports_only_literal_bkpts_in_adjacent_sequence(
        sequence: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that Arm GDB continue reports every literal BKPT in a mixed chain
    while pyOCD services adjacent semihosting BKPTs transparently.

    Test method:
    1. Program the selected S/B chain in executable RAM and start the firmware
       RAM command from its recurring synchronization breakpoint.
    2. Stop at a NOP before the chain, remove that temporary breakpoint, and
       continue once for each expected literal-BKPT stop.
    3. Require each reported stop to have the corresponding B address while
       the mailbox command is still incomplete.
    4. Continue to the firmware completion breakpoint and verify its sequence.

    Expected result: SS has no intervening debugger stop; SB and BS stop once;
    BB stops twice; SBS stops only at its middle B. All commands complete.
    Failure indicates: A semihost BKPT leaked as a stop, a literal BKPT was
    hidden or repeated, or a continue failed to resume the chain.
    """
    output = _run_adjacent_bkpt_sequence(gdbserver_gdb, gdbserver_server, sequence, step_each=False)
    base = _assert_sequence_entry(output)
    stops = re.findall(
        r"GDB-E2E chain-stop=(\d+) pc=0x([0-9a-f]+) completed=(\d+) expected=(\d+)",
        output)
    expected_stops = [index for index, instruction in enumerate(sequence) if instruction == "B"]
    assert len(stops) == len(expected_stops), output
    for (stop_number, program_counter, completed, expected), index in zip(stops, expected_stops):
        assert int(stop_number) == index, output
        assert int(program_counter, 16) == base + _CHAIN_FIRST_BKPT_OFFSET + index * 2, output
        assert completed != expected, output

    _assert_sequence_completed(output)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop-ctrl-c", "non-stop-vCont-t"))
def test_arm_gdb_interrupts_running_between_semihost_and_literal_bkpt(
        non_stop: bool,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that GDB can interrupt a running target after a semihost BKPT and
    still see the following ordinary BKPT after resuming.

    Test method:
    1. Write a short Thumb function into the fixture's executable RAM window.
       It performs SYS_TIME, then counts in a mailbox-controlled gate before
       its ordinary BKPT.
    2. Start RAM_EXECUTE and use an observer GDB to require two different gate
       counter values while the command is incomplete. No host timing decides
       whether the interrupt precedes the ordinary BKPT.
    3. Interrupt through the owner GDB. Require SIGINT in all-stop mode or the
       non-stop vCont;t stop signal, a PC inside the gate, and the SYS_TIME
       result in R0.
    4. Release the gate, resume to the exact ordinary BKPT, then continue to
       the firmware's completion breakpoint.

    Expected result: The semihost operation is serviced, the running target
    stops on request, and the later literal BKPT remains visible exactly once.
    Failure indicates: Semihost resume, requested halt, cached PC comparison,
    or subsequent BKPT reporting lost a stop or advanced the wrong instruction.
    """
    with gdbserver_gdb.start_mi(
            gdbserver_server, "gated-mixed-owner", non_stop=non_stop) as controller, gdbserver_gdb.start(
            gdbserver_server, "gated-mixed-observer", non_stop=non_stop) as observer:
        controller.console("break gdbserver_test_firmware_breakpoint_site")
        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()

        for index, opcode in enumerate(_GATED_MIXED_INSTRUCTIONS):
            controller.console(
                "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[%d] = 0x%04x"
                % (index * 2, opcode))
        for offset, field in _GATED_MIXED_LITERALS:
            controller.console(
                "set {unsigned int}&gdbserver_test_firmware_mailbox.ram_window[%d] = "
                "(unsigned int)&gdbserver_test_firmware_mailbox.%s" % (offset, field))
        address_output = controller.console(
            "printf \"GDB-E2E gate-base=0x%x\\n\", &gdbserver_test_firmware_mailbox.ram_window[0]")
        address = re.search(r"GDB-E2E gate-base=0x([0-9a-f]+)", address_output)
        assert address is not None, address_output
        base = int(address.group(1), 16)
        assert base % 4 == 0, address_output

        sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
        controller.console("set var gdbserver_test_firmware_mailbox.spin_iterations = 0")
        controller.console("set var gdbserver_test_firmware_mailbox.spin_release_sequence = 0")
        controller.console("set var gdbserver_test_firmware_mailbox.command_argument = 0")
        controller.console("set var gdbserver_test_firmware_mailbox.command = %d" % MailboxCommand.RAM_EXECUTE)
        controller.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % sequence)
        controller.continue_execution()
        _wait_for_gated_mixed_execution(observer, sequence)

        interrupted = controller.interrupt()
        expected_signal = "0" if non_stop else "SIGINT"
        assert 'reason="signal-received"' in interrupted, interrupted
        assert 'signal-name="%s"' % expected_signal in interrupted, interrupted
        stopped_output = controller.console(
            "printf \"GDB-E2E gate-stop=0x%x r0=%u state=%u completed=%u\\n\", "
            "$pc, $r0, gdbserver_test_firmware_mailbox.command_state, "
            "gdbserver_test_firmware_mailbox.completed_sequence")
        stopped = re.search(
            r"GDB-E2E gate-stop=0x([0-9a-f]+) r0=(\d+) state=(\d+) completed=(\d+)",
            stopped_output)
        assert stopped is not None, stopped_output
        assert base + _GATED_MIXED_LOOP_START <= int(stopped.group(1), 16) < base + _GATED_MIXED_BKPT_OFFSET, stopped_output
        assert int(stopped.group(2)) != 17, stopped_output
        assert int(stopped.group(3)) == MailboxCommandState.WAITING, stopped_output
        assert int(stopped.group(4)) != sequence, stopped_output

        controller.console("set var gdbserver_test_firmware_mailbox.spin_release_sequence = %d" % sequence)
        controller.continue_execution()
        literal_stop = controller.wait_for_stop()
        assert '*stopped,' in literal_stop, literal_stop
        literal_output = controller.console(
            "printf \"GDB-E2E gate-literal=0x%x completed=%u\\n\", "
            "$pc, gdbserver_test_firmware_mailbox.completed_sequence")
        literal = re.search(r"GDB-E2E gate-literal=0x([0-9a-f]+) completed=(\d+)", literal_output)
        assert literal is not None, literal_output
        assert int(literal.group(1), 16) == base + _GATED_MIXED_BKPT_OFFSET, literal_output
        assert int(literal.group(2)) != sequence, literal_output

        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()
        assert controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == sequence
        observer.detach()
        controller.console("delete breakpoints")
        controller.detach()


def _wait_for_gated_mixed_execution(observer: ExternalGDBSession, sequence: int,
                                    timeout: float = 5.0) -> None:
    """Require semihost completion and two live iterations before interrupting."""
    deadline = time.monotonic() + timeout
    first_iterations = None
    while time.monotonic() < deadline:
        output = observer.execute(
            "printf \"GDB-E2E gate-state=%u iterations=%u completed=%u\\n\", "
            "gdbserver_test_firmware_mailbox.command_state, "
            "gdbserver_test_firmware_mailbox.spin_iterations, "
            "gdbserver_test_firmware_mailbox.completed_sequence")
        status = re.search(
            r"GDB-E2E gate-state=(\d+) iterations=(\d+) completed=(\d+)", output)
        assert status is not None, output
        state, iterations, completed = (int(value) for value in status.groups())
        if state == MailboxCommandState.WAITING and completed != sequence and iterations != 0:
            if first_iterations is not None and iterations != first_iterations:
                return
            first_iterations = iterations
    raise AssertionError("semihost request did not reach the running mailbox gate")


def _run_adjacent_bkpt_sequence(gdb: ExternalGDB, server: PyOCDGDBServer,
                                sequence: str, *, step_each: bool) -> str:
    """Run RAM code with adjacent semihost (S) and literal (B) BKPTs."""
    # Two NOPs keep the first BKPT beyond the temporary entry breakpoint.
    commands = [
        "break gdbserver_test_firmware_breakpoint_site",
        "continue",
        "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[0] = 0x2011",
        "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[2] = 0x2100",
        "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[4] = 0xbf00",
        "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[6] = 0xbf00",
    ]
    for index, instruction in enumerate(sequence):
        opcode = 0xbeab if instruction == "S" else 0xbe00
        commands.append(
            "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[%d] = 0x%04x"
            % (_CHAIN_FIRST_BKPT_OFFSET + index * 2, opcode))
    end = _CHAIN_FIRST_BKPT_OFFSET + len(sequence) * 2
    commands.extend((
        "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[%d] = 0xbf00" % end,
        "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[%d] = 0x4770" % (end + 2),
        "break *&gdbserver_test_firmware_mailbox.ram_window[4]",
        "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1",
        "set var gdbserver_test_firmware_mailbox.command_argument = 0",
        "set var gdbserver_test_firmware_mailbox.command = 14",
        "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence",
        "continue",
        "printf \"GDB-E2E chain-entry=0x%x base=0x%x completed=%u expected=%u\\n\", "
        "$pc, &gdbserver_test_firmware_mailbox.ram_window[0], "
        "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence",
        "delete 2",
    ))
    if step_each:
        commands.extend((
            "stepi",
            "stepi",
            "printf \"GDB-E2E chain-before=0x%x r0=%u\\n\", $pc, $r0",
        ))
        for index, instruction in enumerate(sequence):
            if instruction == "S":
                commands.extend(("set $r0 = 17", "set $r1 = 0"))
            commands.extend((
                "stepi",
                "printf \"GDB-E2E chain-step=%d pc=0x%%x r0=%%u\\n\", $pc, $r0" % index,
            ))
    else:
        for index, instruction in enumerate(sequence):
            if instruction == "B":
                commands.extend((
                    "continue",
                    "printf \"GDB-E2E chain-stop=%d pc=0x%%x completed=%%u expected=%%u\\n\", "
                    "$pc, gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence" % index,
                ))
    commands.extend((
        "continue",
        "printf \"GDB-E2E chain-completed=%u expected=%u\\n\", "
        "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence",
        "delete breakpoints",
        "detach",
    ))
    mode = "step" if step_each else "continue"
    return gdb.run(server, commands, timeout=45.0, artifact_name="adjacent-bkpt-%s-%s" % (mode, sequence.lower()))


def _assert_sequence_entry(output: str) -> int:
    """Require the RAM command to stop at its NOP before the BKPT sequence."""
    entry = re.search(
        r"GDB-E2E chain-entry=0x([0-9a-f]+) base=0x([0-9a-f]+) completed=(\d+) expected=(\d+)",
        output)
    assert entry is not None, output
    base = int(entry.group(2), 16)
    assert int(entry.group(1), 16) == base + 4, output
    assert entry.group(3) != entry.group(4), output
    return base


def _assert_sequence_completed(output: str) -> None:
    """Require firmware completion after the final BKPT operation."""
    completed = re.search(r"GDB-E2E chain-completed=(\d+) expected=(\d+)", output)
    assert completed is not None, output
    assert completed.group(1) == completed.group(2), output

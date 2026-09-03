# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""External GDB compatibility scenario for any supported test target."""

import re

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB


@pytest.mark.gdbserver_external_gdb
def test_external_gdb_loads_and_debugs_the_test_firmware(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Confirm that the selected real GDB executable can load, inspect, pause, and detach from the test firmware normally.
    Test method:
    1. Launch the explicitly selected Arm GDB in a clean batch session and connect with extended-remote.
    2. Issue load so GDB programs the same symbol-bearing AXF through pyOCD's flash protocol.
    3. Inspect loaded files, mailbox memory, the complete register set, and pyOCD monitor status.
    4. Insert a normal breakpoint at the known test firmware site and continue to it twice.
    5. Delete all breakpoints, detach, and require the external process to exit successfully.
    6. Validate the transcript for load progress, symbols, r0, pc, the selected core, breakpoint stops, and detach.
    Expected result: GDB reports the test-firmware AXF, symbols, registers, selected core, breakpoint stops, and detach.
    Failure indicates: pyOCD is incompatible with this selected external GDB workflow.
    Skip: --gdbserver-gdb was not supplied; the runner never auto-selects a GDB executable.
    """
    output = gdbserver_gdb.run(gdbserver_server, (
        "load",
        "info files",
        "x/4wx &gdbserver_test_firmware_mailbox",
        "info registers",
        "monitor status",
        "break gdbserver_test_firmware_breakpoint_site",
        "continue",
        "continue",
        "delete breakpoints",
        "detach",
    ))

    assert gdbserver_server.configuration.firmware.name in output
    assert "Loading section" in output
    assert "gdbserver_test_firmware_mailbox" in output
    # Recognize GDB's hexadecimal r0 register display despite variable spacing.
    assert re.search(r"\br0\s+0x[0-9a-f]+", output, re.IGNORECASE)
    # Recognize GDB's hexadecimal program-counter display despite variable spacing.
    assert re.search(r"\bpc\s+0x[0-9a-f]+", output, re.IGNORECASE)
    # Accept the core number selected for this target rather than assuming core 0.
    assert re.search(r"\bCore\s+\d+\b", output)
    assert output.count("Breakpoint 1") >= 3
    assert (
        "Detaching from program" in output
        # Accept GDB's alternate remote-inferior detach message and its numeric ID.
        or re.search(r"\[Inferior \d+ \(Remote target\) detached\]", output)
    )

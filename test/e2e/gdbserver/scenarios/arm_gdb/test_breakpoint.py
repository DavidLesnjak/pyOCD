# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Hardware-breakpoint scenarios exercised through arm-none-eabi-gdb."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_single_client_workflow


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

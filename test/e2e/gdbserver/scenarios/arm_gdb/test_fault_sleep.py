# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Fault scenarios exercised through arm-none-eabi-gdb."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_single_client_workflow


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(vector_catch="h")
def test_hardfault_vector_catch_and_reset_recovery(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that Arm GDB observes a deliberate HardFault and can recover the target with monitor reset.
    Test method:
    1. Start pyOCD with HardFault vector catch and connect the selected Arm GDB.
    2. Synchronize at the recurring breakpoint and queue the target-side HARDFAULT command through GDB assignments.
    3. Continue into the undefined instruction and require GDB to report SIGSEGV with the test firmware's deliberate-fault function in the backtrace.
    4. Record the pre-reset boot epoch, issue monitor reset, and continue to the recurring breakpoint after firmware initialization.
    5. Require the boot epoch to advance exactly once, inspect the recovered PC, remove breakpoints, and detach.
    Expected result: Vector catch reports the deliberate HardFault through GDB and monitor reset publishes exactly one new debuggable firmware generation.
    Failure indicates: Arm GDB fault reporting, vector catch, backtrace, or reset recovery is incorrect.
    """
    run_single_client_workflow("hardfault", gdbserver_gdb, gdbserver_server)

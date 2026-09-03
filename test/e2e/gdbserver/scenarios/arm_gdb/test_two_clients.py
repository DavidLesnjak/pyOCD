# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Arm-GDB multi-client read-only observation scenarios."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_multi_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_two_clients_can_read_the_test_firmware(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that two real Arm GDB processes can share one pyOCD target while one owns execution.
    Test method:
    1. Start an asynchronous controller GDB and a separate observer GDB before the test operation.
    2. Synchronize the controller, queue SPIN through GDB assignments, and continue asynchronously.
    3. Read the live spin counter through the observer and require non-zero progress.
    4. Interrupt through the controller and read pc through the observer while the target is stopped.
    5. Release SPIN through the controller, continue to the synchronization breakpoint, and require exact completion.
    Expected result: The observer reads shared target state without taking execution ownership and SPIN completes normally.
    Failure indicates: Multiple external-GDB sessions cannot safely observe and control the same target.
    """
    run_multi_client_workflow("two-client-read", gdbserver_gdb, gdbserver_server)

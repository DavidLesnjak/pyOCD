# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Basic target-inspection scenarios exercised through arm-none-eabi-gdb."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_multi_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_mailbox_memory_registers_and_spin(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that one standard Arm GDB controller can inspect the test mailbox and
    registers, interrupt a confirmed-running command, and release it to completion.

    Test method:
    1. Start Arm GDB in asynchronous MI mode and synchronize at the recurring
       test-firmware breakpoint.
    2. Read the mailbox magic and ABI through GDB expression evaluation and require
       their exact values.
    3. Run ``info registers r0 pc`` and require valid hexadecimal values in the
       controller transcript.
    4. Connect a temporary standard GDB observer while the controller is stopped.
    5. Queue SPIN through controller GDB assignments, continue asynchronously, and
       poll the observer mailbox view until target-side iterations are non-zero.
    6. Detach the observer, interrupt the confirmed-running SPIN through the
       controller, and require non-zero iterations after its stop.
    7. Write the matching release sequence, continue to the synchronization
       breakpoint, and require exact command completion.

    Expected result:
    GDB reads valid mailbox/register state, interrupts a physically running SPIN,
    and releases the same command to completion.

    Failure indicates:
    Basic Arm GDB memory/register access, cross-client observation, asynchronous
    execution control, interrupt delivery, or mailbox interoperability is broken.
    """
    run_multi_client_workflow("mailbox-spin", gdbserver_gdb, gdbserver_server)

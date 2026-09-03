# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Reset scenarios exercised through arm-none-eabi-gdb."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_multi_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_target_reset_survives_disconnect_and_reconnect(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a real Arm GDB client can reset, detach, reconnect, and observe a new firmware boot generation.
    Test method:
    1. Start an asynchronous Arm GDB client and synchronize at the recurring firmware breakpoint.
    2. Read the current retained boot epoch through GDB/MI.
    3. Issue monitor reset, detach the original client, and require persistent gdbserver to remain alive.
    4. Start a replacement Arm GDB client and synchronize after firmware initialization.
    5. Read the new boot epoch and require an exact unsigned increment from the pre-reset value.
    Expected result: Reset advances the boot epoch and the same persistent server accepts a functioning replacement GDB.
    Failure indicates: Monitor reset, final-client detach, target restart, or external-GDB reconnection is broken.
    """
    run_multi_client_workflow("monitor-reset-reconnect", gdbserver_gdb, gdbserver_server)

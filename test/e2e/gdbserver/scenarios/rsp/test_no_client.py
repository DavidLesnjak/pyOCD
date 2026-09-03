# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Initial no-client gdbserver scenario for the B-U585I-IOT02A."""

import json
import time

from mailbox import FixtureMailboxClient, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer


def test_server_runs_test_firmware_before_a_gdb_client_connects(gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a persistent server starts and lets the test firmware run even before a debugger connects.
    Test method:
    1. Start the persistent server with reset-run but do not create any RSP or GDB client.
    2. Read run.json and verify the cbuild target and selected dynamic GDB port.
    3. Wait for a bounded interval during which the test firmware can execute without a debugger.
    4. Make the first RSP connection, which halts the target, and locate the mailbox from the ELF symbol.
    5. Require valid readiness fields plus non-zero heartbeat and loop counters accumulated before attachment.
    Expected result: The server remains alive, metadata names STM32U585AIIx, and heartbeat/loop counts are non-zero.
    Failure indicates: Target progress depends on client attachment or server metadata is inconsistent.
    """
    run_metadata_path = gdbserver_server.configuration.artifacts.directory / "run.json"
    run_metadata = json.loads(run_metadata_path.read_text(encoding="utf-8"))

    assert gdbserver_server.is_running
    assert run_metadata["cbuild_target_type"] == "STM32U585AIIx"
    assert run_metadata["gdb_port"] == gdbserver_server.configuration.gdb_port

    # No RSP client is connected during this interval. The first connection
    # deliberately halts the target, so its non-zero counters demonstrate that
    # the fixture was running independently of any GDB client.
    time.sleep(0.250)
    mailbox_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_mailbox")
    with gdbserver_server.connect_rsp() as client:
        mailbox = FixtureMailboxClient(client, mailbox_address).wait_until_ready()

    assert mailbox.heartbeat != 0
    assert mailbox.loop_count != 0

# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Host-only tests for the reusable gdbserver E2E runner components."""

from contextlib import contextmanager
import json
from pathlib import Path
import socket
import struct
import threading
import time
from typing import Callable, Iterator

import pytest

import pyocd_server
from pyocd.utility.cmdline import convert_session_options
from artifacts import RunArtifacts
from mailbox import (
    FIXTURE_ABI_VERSION,
    FIXTURE_MAGIC,
    MAILBOX_HEADER_FORMAT,
    MAILBOX_RAM_WINDOW_SIZE,
    MAILBOX_SIZE,
    FixtureMailbox,
    MailboxCommand,
    MailboxCommandState,
    MailboxResult,
)
from pyocd_server import GDBServerConfiguration, PyOCDGDBServer
from rsp import RSPClient, RSPPacket, RSPProtocolError
from scenario_docs import validate_scenario_docstring
from stream import TCPStreamClient, TCPStreamConnectionError


def test_artifact_storage_creates_a_distinct_run_directory(
        tmp_path: Path) -> None:
    """Each attempt has an independent directory and structured artifacts."""
    artifacts = RunArtifacts.create(
        tmp_path, "B-U585I-IOT02A", "mailbox smoke")

    artifacts.write_json("run.json", {"status": "PASS"})
    artifacts.append_json_line("rsp.jsonl", {"payload": "qSupported"})
    artifacts.append_bytes("streams/rtt.bin", b"RTT:00000001\n")

    assert artifacts.directory.is_dir()
    assert (artifacts.directory / "run.json").is_file()
    assert (artifacts.directory / "rsp.jsonl").is_file()
    assert (artifacts.directory / "streams" / "rtt.bin").read_bytes() == (
        b"RTT:00000001\n")


def test_scenario_documentation_contract_accepts_numbered_procedure() -> None:
    """The documentation parser accepts the complete scenario contract."""
    validate_scenario_docstring(
        """
        Purpose: Exercise one deterministic behavior.
        Test method:
        1. Establish the initial state.
        2. Perform the operation and inspect its result.
        Expected result: The stated behavior is observed.
        Failure indicates: The behavior did not match its contract.
        """,
        "test_documented_scenario")


def test_scenario_documentation_contract_rejects_unnumbered_method() -> None:
    """The documentation parser rejects prose that cannot expose ordered steps."""
    with pytest.raises(ValueError, match="at least two numbered steps"):
        validate_scenario_docstring(
            """
            Purpose: Exercise one deterministic behavior.
            Test method: Perform the operation without explicit steps.
            Expected result: The stated behavior is observed.
            Failure indicates: The behavior did not match its contract.
            """,
            "test_undocumented_scenario")


def test_mailbox_decoder_matches_fixture_abi() -> None:
    """The host decoder remains synchronized with the C fixture layout."""
    header = list(range(46))
    header[0] = FIXTURE_MAGIC
    header[1] = FIXTURE_ABI_VERSION
    header[2] = 7
    data = (struct.pack(MAILBOX_HEADER_FORMAT, *header) +
            bytes(range(MAILBOX_RAM_WINDOW_SIZE)))
    mailbox = FixtureMailbox.from_bytes(data)

    assert len(data) == MAILBOX_SIZE
    assert mailbox.magic == FIXTURE_MAGIC
    assert mailbox.is_ready
    assert mailbox.boot_epoch == 7
    assert (
        mailbox.heartbeat,
        mailbox.loop_count,
        mailbox.command,
        mailbox.command_sequence,
        mailbox.completed_sequence,
        mailbox.result,
        mailbox.command_argument,
        mailbox.command_state,
        mailbox.rtt_messages,
        mailbox.rtt_sequence,
        mailbox.rtt_input_bytes,
        mailbox.rtt_input_checksum,
        mailbox.rtt_dropped_bytes,
        mailbox.rtt_burst_messages,
        mailbox.rtt_burst_sequence,
        mailbox.rtt_burst_dropped_bytes,
        mailbox.itm_messages,
        mailbox.itm_sequence,
        mailbox.semihosting_console_calls,
        mailbox.semihosting_file_calls,
        mailbox.semihosting_open_result,
        mailbox.semihosting_write_remaining,
        mailbox.semihosting_close_result,
        mailbox.semihosting_errno,
        mailbox.literal_bkpt_calls,
        mailbox.wfi_calls,
        mailbox.wfi_state,
        mailbox.wfi_wake_count,
        mailbox.wfi_wake_irq,
        mailbox.hardfault_calls,
        mailbox.system_reset_calls,
        mailbox.spin_iterations,
        mailbox.spin_state,
        mailbox.spin_release_sequence,
        mailbox.step_result,
        mailbox.watchpoint_value,
        mailbox.watchpoint_reads,
        mailbox.watchpoint_writes,
        mailbox.transport_stream_sequence,
        mailbox.transport_stream_rtt_messages,
        mailbox.transport_stream_rtt_dropped_bytes,
        mailbox.transport_stream_semihosting_messages,
        mailbox.transport_stream_semihosting_failures,
    ) == tuple(range(3, 46))
    assert mailbox.ram_window == bytes(range(MAILBOX_RAM_WINDOW_SIZE))
    assert MAILBOX_HEADER_FORMAT == "<46I"


def test_mailbox_reset_ready_requires_new_idle_generation() -> None:
    """A reset-ready mailbox has the requested boot epoch and reset command state."""
    header = [0] * 46
    header[0] = FIXTURE_MAGIC
    header[1] = FIXTURE_ABI_VERSION
    header[2] = 8
    data = (struct.pack(MAILBOX_HEADER_FORMAT, *header) +
            bytes(MAILBOX_RAM_WINDOW_SIZE))
    mailbox = FixtureMailbox.from_bytes(data)

    assert mailbox.is_reset_ready(8)
    assert not mailbox.is_reset_ready(7)

    header[5] = MailboxCommand.STEP
    header[6] = 1
    header[8] = MailboxResult.IN_PROGRESS
    header[10] = MailboxCommandState.EXECUTING
    active_mailbox = FixtureMailbox.from_bytes(
        struct.pack(MAILBOX_HEADER_FORMAT, *header) +
        bytes(MAILBOX_RAM_WINDOW_SIZE))
    assert not active_mailbox.is_reset_ready(8)


def test_rsp_client_handles_acknowledged_command() -> None:
    """The client validates an acknowledged command/response exchange."""
    def _serve(connection: socket.socket) -> None:
        request = _receive_packet(connection)
        assert _packet_payload(request) == b"qSupported"
        connection.sendall(b"+" + _packet(b"OK"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            assert client.command(b"qSupported") == b"OK"


def test_rsp_client_retries_after_a_negative_acknowledgement() -> None:
    """A negative acknowledgement retransmits the original request packet."""
    def _serve(connection: socket.socket) -> None:
        first_request = _receive_packet(connection)
        connection.sendall(b"-")
        second_request = _receive_packet(connection)
        assert second_request == first_request
        connection.sendall(b"+" + _packet(b"OK"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            assert client.command(b"qSupported") == b"OK"


def test_rsp_client_handles_fragmented_packet_responses() -> None:
    """A response split across TCP receives is reconstructed before validation."""
    def _serve(connection: socket.socket) -> None:
        assert _packet_payload(_receive_packet(connection)) == b"qC"
        response = _packet(b"QC1")
        connection.sendall(b"+")
        connection.sendall(response[:2])
        time.sleep(0.010)
        connection.sendall(response[2:])
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            assert client.command(b"qC") == b"QC1"


def test_rsp_client_rejects_bad_response_checksum() -> None:
    """A bad reply checksum produces an error and a negative acknowledgement."""
    def _serve(connection: socket.socket) -> None:
        assert _packet_payload(_receive_packet(connection)) == b"qC"
        connection.sendall(b"+$QC1#00")
        assert _receive_exact(connection, 1) == b"-"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            with pytest.raises(RSPProtocolError, match="checksum"):
                client.command(b"qC")


def test_rsp_client_enables_no_ack_after_negotiation() -> None:
    """No-ack negotiation retains the reply ACK, then suppresses later ones."""
    def _serve(connection: socket.socket) -> None:
        assert (_packet_payload(_receive_packet(connection)) ==
                b"QStartNoAckMode")
        connection.sendall(b"+" + _packet(b"OK"))
        assert _receive_exact(connection, 1) == b"+"

        assert _packet_payload(_receive_packet(connection)) == b"qC"
        connection.sendall(_packet(b"QC1"))
        connection.settimeout(0.100)
        try:
            following = connection.recv(1)
        except socket.timeout:
            following = b""
        assert following != b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            client.enable_no_ack_mode()
            assert client.command(b"qC") == b"QC1"


def test_rsp_client_preserves_non_stop_notification_packet_type() -> None:
    """Non-stop notifications remain distinct from ordinary response packets."""
    def _serve(connection: socket.socket) -> None:
        assert _packet_payload(_receive_packet(connection)) == b"vCont;c"
        connection.sendall(
            b"+" + _packet(b"Stop:T0507:00100020;", packet_type=b"%"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            client.send_packet(b"vCont;c")
            response = client.receive_packet_with_type()

    assert isinstance(response, RSPPacket)
    assert response.packet_type == "%"
    assert response.payload.startswith(b"Stop:T05")


def test_rsp_client_defers_notification_that_arrives_before_command_reply() -> None:
    """An asynchronous notification cannot be mistaken for a command response."""
    def _serve(connection: socket.socket) -> None:
        assert _packet_payload(_receive_packet(connection)) == b"qC"
        connection.sendall(
            _packet(b"Stop:T0507:00100020;", packet_type=b"%") +
            b"+" +
            _packet(b"QC1"))
        assert _receive_exact(connection, 1) == b"+"
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            assert client.command(b"qC") == b"QC1"
            notification = client.receive_packet_with_type()

    assert notification.packet_type == "%"
    assert notification.payload.startswith(b"Stop:T05")


def test_rsp_client_uses_unescaped_qxfer_length_for_the_next_offset() -> None:
    """qXfer offsets advance by data bytes, not escaped wire-byte counts."""
    def _serve(connection: socket.socket) -> None:
        first_request = _packet_payload(_receive_packet(connection))
        assert first_request == b"qXfer:features:read:target.xml:0,8"
        connection.sendall(b"+" + _packet(b"mA}\x03}\x04"))
        assert _receive_exact(connection, 1) == b"+"

        second_request = _packet_payload(_receive_packet(connection))
        assert second_request == b"qXfer:features:read:target.xml:3,8"
        connection.sendall(b"+" + _packet(b"l}]}\n"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            assert client.read_xfer(
                "features", "target.xml", chunk_size=8) == b"A#$}*"


def test_rsp_client_escapes_binary_memory_write_data() -> None:
    """The X packet escapes all reserved RSP payload characters."""
    def _serve(connection: socket.socket) -> None:
        payload = _packet_payload(_receive_packet(connection))
        assert payload == b"X20000000,4:}\x03}\x04}]}\n"
        connection.sendall(b"+" + _packet(b"OK"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            client.write_memory_binary(0x20000000, b"#$}*")


def test_rsp_client_decodes_monitor_response() -> None:
    """A qRcmd response is decoded from its hexadecimal text representation."""
    def _serve(connection: socket.socket) -> None:
        assert (_packet_payload(_receive_packet(connection)) ==
                b"qRcmd,76657273696f6e")
        connection.sendall(b"+" + _packet(b"70794f434420746573740a"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            assert client.monitor("version") == "pyOCD test\n"


def test_rsp_client_sends_replyless_extended_reset() -> None:
    """An extended reset waits for its acknowledgement but not a reply packet."""
    def _serve(connection: socket.socket) -> None:
        assert _packet_payload(_receive_packet(connection)) == b"!"
        connection.sendall(b"+" + _packet(b"OK"))
        assert _receive_exact(connection, 1) == b"+"

        assert _packet_payload(_receive_packet(connection)) == b"R0"
        connection.sendall(b"+")

        assert _packet_payload(_receive_packet(connection)) == b"?"
        connection.sendall(b"+" + _packet(b"T05"))
        assert _receive_exact(connection, 1) == b"+"

    with _rsp_server(_serve) as port:
        with RSPClient.connect("127.0.0.1", port) as client:
            client.extended_reset()


def test_gdbserver_configuration_serializes_numeric_session_options(
        tmp_path: Path) -> None:
    """Typed -O values remain valid command-line scalars for pyOCD."""
    configuration = _configuration(
        tmp_path,
        enable_swv=True,
        vector_catch="h")
    server = PyOCDGDBServer(configuration)

    options = dict(server._session_option_arguments())
    parsed = convert_session_options(
        [name + "=" + value for name, value in options.items()])
    command = server._gdbserver_command()

    assert configuration.enable_semihosting
    assert not configuration.semihost_use_syscalls
    assert "--semihosting" in command
    assert options["stdio_mode"] == "server"
    assert command[command.index("--vector-catch") + 1] == "h"
    assert options["enable_swv"] == "true"
    assert options["swv_system_clock"] == "160000000"
    assert options["swv_clock"] == "2000000"
    assert options["swv_raw_port"] == str(configuration.swv_raw_port)
    assert parsed["swv_system_clock"] == 160000000
    assert parsed["swv_clock"] == 2000000
    assert parsed["swv_raw_port"] == configuration.swv_raw_port


def test_gdbserver_configuration_builds_address_rtt_option(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Address-mode RTT emits an option pyOCD parses as the expected mapping."""
    monkeypatch.setattr(
        pyocd_server,
        "resolve_elf_symbol",
        lambda firmware, symbol: 0x20001234)
    configuration = _configuration(tmp_path, rtt_mode="address")
    options = dict(PyOCDGDBServer(configuration)._session_option_arguments())
    parsed = convert_session_options(
        [name + "=" + value for name, value in options.items()])

    assert configuration.rtt_control_block_address == 0x20001234
    assert parsed["rtt"] == ({
        "channel": [
            {
                "number": 0,
                "mode": "server",
                "port": configuration.rtt_port,
            },
            {
                "number": 1,
                "mode": "server",
                "port": configuration.rtt_burst_port,
            },
        ],
        "control-block": {"address": 0x20001234},
    },)
    assert configuration.rtt_port != 0
    assert configuration.rtt_burst_port != 0
    assert configuration.rtt_burst_port != configuration.rtt_port


def test_gdbserver_configuration_records_both_rtt_channel_ports(
        tmp_path: Path) -> None:
    """Run metadata identifies the scenario, revision, options, and RTT ports."""
    configuration = _configuration(tmp_path, rtt_mode="symbol")
    server = PyOCDGDBServer(configuration)
    server._write_run_metadata(())
    metadata = json.loads(
        (configuration.artifacts.directory / "run.json").read_text(encoding="utf-8"))

    assert metadata["rtt_mode"] == "symbol"
    assert metadata["rtt_port"] == configuration.rtt_port
    assert metadata["rtt_burst_port"] == configuration.rtt_burst_port
    assert metadata["scenario_id"] == "configuration"
    assert metadata["random_seed"] is None
    assert metadata["python_executable"] == configuration.python_executable
    assert metadata["pyocd_version"]
    assert metadata["effective_session_options"]["rtt"]


def test_gdbserver_records_rsp_connection_identity(
        tmp_path: Path) -> None:
    """Packet artifacts retain the RSP connection that produced each event."""
    configuration = _configuration(tmp_path)
    server = PyOCDGDBServer(configuration)
    server._record_rsp_packet(
        7,
        RSPPacket(1.0, "receive", "$", b"qC"))

    record = json.loads(
        (configuration.artifacts.directory / "rsp.jsonl").read_text(encoding="utf-8"))
    assert record["connection_id"] == 7
    assert record["direction"] == "receive"
    assert record["payload_hex"] == b"qC".hex()


def test_gdbserver_configuration_rejects_empty_scenario_id(
        tmp_path: Path) -> None:
    """Every hardware artifact must identify its originating scenario."""
    with pytest.raises(ValueError, match="scenario_id must not be empty"):
        _configuration(tmp_path, scenario_id="")


@pytest.mark.parametrize("overrides", (
    {"gdb_port": 43210, "telnet_port": 43210},
    {"rtt_mode": "symbol", "rtt_port": 43210, "rtt_burst_port": 43210},
    {"rtt_mode": "symbol", "gdb_port": 43210, "rtt_burst_port": 43210},
))
def test_gdbserver_configuration_rejects_conflicting_tcp_ports(
        tmp_path: Path, overrides: dict[str, object]) -> None:
    """A server cannot bind two protocol endpoints to one TCP port."""
    with pytest.raises(ValueError, match="ports must be different"):
        _configuration(tmp_path, **overrides)


def test_tcp_stream_client_collects_fragmented_cumulative_data() -> None:
    """Stream reads retain all data and notify the artifact observer per read."""
    observed: list[bytes] = []

    def _serve(connection: socket.socket) -> None:
        connection.sendall(b"RT")
        assert _receive_exact(connection, 1) == b"1"
        connection.sendall(b"T:00000001\n")

    with _tcp_stream_server(_serve) as port:
        with TCPStreamClient.connect(
                "127.0.0.1", port, data_observer=observed.append) as stream:
            assert stream.read_available(timeout=1.0) == b"RT"
            stream.send(b"1")
            assert stream.read_until(b"RTT:00000001\n") == b"RTT:00000001\n"

    assert observed == [b"RT", b"T:00000001\n"]


def test_tcp_stream_client_handles_quiet_and_closed_streams() -> None:
    """A quiet stream is distinguishable from a peer that has closed it."""
    def _wait_for_client_close(connection: socket.socket) -> None:
        assert _receive_exact(connection, 1) == b"!"

    with _tcp_stream_server(_wait_for_client_close) as port:
        with TCPStreamClient.connect("127.0.0.1", port) as stream:
            assert stream.read_available(timeout=0.010) == b""
            with pytest.raises(ValueError, match="must not be empty"):
                stream.read_until(b"")
            stream.send(b"!")

    with _tcp_stream_server(lambda connection: None) as port:
        with TCPStreamClient.connect("127.0.0.1", port) as stream:
            with pytest.raises(TCPStreamConnectionError, match="closed"):
                stream.read_available(timeout=1.0)


@contextmanager
def _rsp_server(handler: Callable[[socket.socket], None]) -> Iterator[int]:
    """Run one scripted RSP peer and surface its assertion failures."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1.0)
    port = int(listener.getsockname()[1])
    errors: list[BaseException] = []

    def _serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                handler(connection)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=_serve)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert not errors


@contextmanager
def _tcp_stream_server(handler: Callable[[socket.socket], None]) -> Iterator[int]:
    """Run one scripted TCP stream peer and surface its assertion failures."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1.0)
    port = int(listener.getsockname()[1])
    errors: list[BaseException] = []

    def _serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                handler(connection)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=_serve)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert not errors


def _configuration(tmp_path: Path, **overrides: object) -> GDBServerConfiguration:
    """Create a valid local configuration without relying on board build outputs."""
    cbuild_run = tmp_path / "fixture.cbuild-run.yml"
    cbuild_run.write_text("cbuild-run: {}\n", encoding="utf-8")
    firmware = tmp_path / "fixture.axf"
    firmware.write_bytes(b"fixture")
    arguments: dict[str, object] = {
        "probe_uid": "probe",
        "cbuild_run": cbuild_run,
        "artifacts": RunArtifacts.create(tmp_path / "artifacts", "target", "configuration"),
        "repository_root": tmp_path,
        "scenario_id": "configuration",
        "firmware": firmware,
    }
    arguments.update(overrides)
    return GDBServerConfiguration(**arguments)


def _packet(payload: bytes, packet_type: bytes = b"$") -> bytes:
    """Encode one packet sent by the scripted peer."""
    checksum = ("%02x" % (sum(payload) % 256)).encode("ascii")
    return packet_type + payload + b"#" + checksum


def _packet_payload(packet: bytes) -> bytes:
    """Extract a raw payload from a complete scripted-client request packet."""
    assert packet[:1] == b"$"
    assert packet[-3:-2] == b"#"
    return packet[1:-3]


def _receive_packet(connection: socket.socket) -> bytes:
    """Read exactly one raw RSP packet from the scripted peer socket."""
    packet = bytearray()
    while True:
        value = _receive_exact(connection, 1)
        packet.extend(value)
        if value == b"#":
            packet.extend(_receive_exact(connection, 2))
            return bytes(packet)


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    """Read exactly ``length`` bytes or allow the socket timeout to surface."""
    data = bytearray()
    while len(data) < length:
        block = connection.recv(length - len(data))
        if not block:
            raise ConnectionError("scripted RSP peer closed the connection")
        data.extend(block)
    return bytes(data)

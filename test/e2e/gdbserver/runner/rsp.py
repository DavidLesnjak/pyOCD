# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Small deterministic GDB Remote Serial Protocol client.

The runner intentionally uses this client for protocol-level scenarios. It does
not replace real GDB compatibility tests, which use an external GDB process.
"""

from __future__ import annotations

from dataclasses import dataclass
import socket
import time
from typing import Callable, Optional


class RSPError(RuntimeError):
    """Base error for a GDB Remote Serial Protocol exchange."""


class RSPConnectionClosedError(RSPError):
    """Raised when the server closes the RSP connection."""


class RSPProtocolError(RSPError):
    """Raised for malformed or invalid RSP traffic."""


class RSPTimeoutError(RSPError):
    """Raised when an RSP operation reaches its deadline."""


class RSPRemoteError(RSPError):
    """Raised when the RSP server returns an E-style error response."""


@dataclass(frozen=True)
class RSPPacket:
    """A packet observed on the RSP connection."""

    timestamp: float
    direction: str
    packet_type: str
    payload: bytes


PacketObserver = Callable[[RSPPacket], None]


class RSPClient:
    """Synchronous RSP client with packet validation and a timestamped observer."""

    def __init__(self, connection: socket.socket, timeout: float = 5.0,
                 packet_observer: Optional[PacketObserver] = None) -> None:
        self._connection = connection
        self._timeout = timeout
        self._packet_observer = packet_observer
        self._receive_buffer = bytearray()
        self._pending_packets: list[RSPPacket] = []
        self._send_acks = True
        self._closed = False

    @classmethod
    def connect(cls, host: str, port: int, timeout: float = 5.0,
                packet_observer: Optional[PacketObserver] = None) -> "RSPClient":
        """Connect to an RSP server."""
        connection = socket.create_connection((host, port), timeout=timeout)
        return cls(connection, timeout=timeout, packet_observer=packet_observer)

    def close(self) -> None:
        """Close the RSP connection."""
        if self._closed:
            return

        self._closed = True
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._connection.close()

    def __enter__(self) -> "RSPClient":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def enable_no_ack_mode(self) -> None:
        """Negotiate QStartNoAckMode after the connection is established."""
        response = self.command(b"QStartNoAckMode")
        if response != b"OK":
            raise RSPProtocolError("server rejected QStartNoAckMode: %r" % response)
        self._send_acks = False

    def command(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        """Send a request packet and return one response packet payload."""
        response = self.command_response(payload, timeout=timeout)
        if response.startswith(b"E"):
            raise RSPRemoteError(response.decode("ascii", errors="replace"))
        return response

    def command_response(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        """Send a request packet and return its response, including E-style errors."""
        deadline = self._deadline(timeout)
        self.send_packet(payload, deadline=deadline)
        while True:
            response = self._take_pending_response()
            if response is not None:
                return response.payload

            packet = self._receive_packet_from_wire(deadline)
            if packet.packet_type == "$":
                return packet.payload
            self._pending_packets.append(packet)

    def send_packet(self, payload: bytes, timeout: Optional[float] = None,
                    deadline: Optional[float] = None) -> None:
        """Send one RSP request without waiting for its response."""
        if self._closed:
            raise RSPConnectionClosedError("RSP connection is closed")

        if deadline is None:
            deadline = self._deadline(timeout)

        packet = b"$" + payload + b"#" + self._checksum(payload)
        attempts = 0
        while True:
            self._send(packet, deadline)
            self._observe_packet(RSPPacket(time.monotonic(), "send", "$", payload))
            if not self._send_acks:
                return

            acknowledgement = self._receive_acknowledgement(deadline)
            if acknowledgement == b"+":
                return
            attempts += 1
            if attempts == 3:
                raise RSPProtocolError("server rejected RSP packet three times")

    def receive_packet(self, timeout: Optional[float] = None,
                       deadline: Optional[float] = None) -> bytes:
        """Receive and verify one normal or notification RSP packet."""
        return self.receive_packet_with_type(timeout=timeout, deadline=deadline).payload

    def receive_packet_with_type(self, timeout: Optional[float] = None,
                                 deadline: Optional[float] = None) -> RSPPacket:
        """Receive one RSP packet and preserve whether it was a reply or notification."""
        if self._closed:
            raise RSPConnectionClosedError("RSP connection is closed")

        if deadline is None:
            deadline = self._deadline(timeout)

        if self._pending_packets:
            return self._pending_packets.pop(0)
        return self._receive_packet_from_wire(deadline)

    def _receive_packet_from_wire(self, deadline: float) -> RSPPacket:
        """Receive one packet directly from the connection, bypassing queued events."""
        while True:
            packet_start = self._find_packet_start()
            if packet_start is None:
                self._receive_more(deadline)
                continue

            if packet_start:
                del self._receive_buffer[:packet_start]

            packet_type = chr(self._receive_buffer[0])
            checksum_index = self._receive_buffer.find(b"#", 1)
            if checksum_index == -1 or len(self._receive_buffer) < checksum_index + 3:
                self._receive_more(deadline)
                continue

            payload = bytes(self._receive_buffer[1:checksum_index])
            received_checksum = bytes(self._receive_buffer[checksum_index + 1:checksum_index + 3])
            del self._receive_buffer[:checksum_index + 3]

            if received_checksum.lower() != self._checksum(payload):
                if self._send_acks:
                    self._send(b"-", deadline)
                raise RSPProtocolError("invalid RSP packet checksum")

            if self._send_acks:
                self._send(b"+", deadline)
            packet = RSPPacket(time.monotonic(), "receive", packet_type, payload)
            self._observe_packet(packet)
            return packet

    def interrupt(self, timeout: Optional[float] = None) -> None:
        """Send the out-of-band Ctrl-C interrupt character."""
        deadline = self._deadline(timeout)
        self._send(b"\x03", deadline)
        self._observe_packet(RSPPacket(time.monotonic(), "send", "interrupt", b"\x03"))

    def read_memory(self, address: int, length: int, timeout: Optional[float] = None) -> bytes:
        """Read target memory using the RSP m packet."""
        response = self.command(("m%x,%x" % (address, length)).encode("ascii"), timeout=timeout)
        try:
            data = bytes.fromhex(response.decode("ascii"))
        except ValueError as error:
            raise RSPProtocolError("invalid hexadecimal memory response") from error
        if len(data) != length:
            raise RSPProtocolError("expected %d memory bytes, received %d" % (length, len(data)))
        return data

    def write_memory(self, address: int, data: bytes, timeout: Optional[float] = None) -> None:
        """Write target memory using the RSP M packet."""
        payload = ("M%x,%x:" % (address, len(data))).encode("ascii") + data.hex().encode("ascii")
        response = self.command(payload, timeout=timeout)
        if response != b"OK":
            raise RSPProtocolError("unexpected memory-write response: %r" % response)

    def write_memory_binary(self, address: int, data: bytes,
                            timeout: Optional[float] = None) -> None:
        """Write target memory using RSP X packet escaping rules."""
        payload = ("X%x,%x:" % (address, len(data))).encode("ascii") + self._escape_binary(data)
        response = self.command(payload, timeout=timeout)
        if response != b"OK":
            raise RSPProtocolError("unexpected binary memory-write response: %r" % response)

    def read_registers(self, timeout: Optional[float] = None) -> bytes:
        """Read the raw target register block using the RSP g packet."""
        response = self.command(b"g", timeout=timeout)
        try:
            return bytes.fromhex(response.decode("ascii"))
        except ValueError as error:
            raise RSPProtocolError("invalid hexadecimal register response") from error

    def read_register(self, register_number: int, timeout: Optional[float] = None) -> bytes:
        """Read one raw target register using the RSP p packet."""
        if register_number < 0:
            raise ValueError("register number must not be negative")
        response = self.command(("p%x" % register_number).encode("ascii"), timeout=timeout)
        try:
            return bytes.fromhex(response.decode("ascii"))
        except ValueError as error:
            raise RSPProtocolError("invalid hexadecimal single-register response") from error

    def write_register(self, register_number: int, value: bytes,
                       timeout: Optional[float] = None) -> None:
        """Write one raw target register using the RSP P packet."""
        if register_number < 0:
            raise ValueError("register number must not be negative")
        payload = ("P%x=" % register_number).encode("ascii") + value.hex().encode("ascii")
        response = self.command(payload, timeout=timeout)
        if response != b"OK":
            raise RSPProtocolError("unexpected single-register write response: %r" % response)

    def write_registers(self, values: bytes, timeout: Optional[float] = None) -> None:
        """Write a raw target register block using the RSP G packet."""
        response = self.command(b"G" + values.hex().encode("ascii"), timeout=timeout)
        if response != b"OK":
            raise RSPProtocolError("unexpected register-block write response: %r" % response)

    def monitor(self, command: str, timeout: Optional[float] = None) -> str:
        """Run a pyOCD monitor command through qRcmd and decode its output."""
        payload = b"qRcmd," + command.encode("utf-8").hex().encode("ascii")
        response = self.command(payload, timeout=timeout)
        try:
            return bytes.fromhex(response.decode("ascii")).decode("utf-8", errors="replace")
        except ValueError as error:
            raise RSPProtocolError("invalid qRcmd response") from error

    def read_xfer(self, object_name: str, annex: str, chunk_size: int = 256,
                  timeout: Optional[float] = None) -> bytes:
        """Read a complete qXfer object while respecting RSP packet escaping."""
        if chunk_size <= 0:
            raise ValueError("qXfer chunk size must be positive")
        offset = 0
        data = bytearray()
        while True:
            payload = ("qXfer:%s:read:%s:%x,%x" %
                       (object_name, annex, offset, chunk_size)).encode("ascii")
            response = self.command(payload, timeout=timeout)
            if response[:1] not in (b"m", b"l"):
                raise RSPProtocolError("invalid qXfer response: %r" % response)
            fragment = self._unescape_binary(response[1:])
            data.extend(fragment)
            if response[:1] == b"l":
                return bytes(data)
            if not fragment:
                raise RSPProtocolError("qXfer returned an empty continuation fragment")
            offset += len(fragment)

    def detach(self, timeout: Optional[float] = None) -> None:
        """Request normal RSP detach and verify the server accepts it."""
        response = self.command(b"D", timeout=timeout)
        if response != b"OK":
            raise RSPProtocolError("unexpected detach response: %r" % response)

    def extended_reset(self, timeout: Optional[float] = None) -> None:
        """Enter extended mode, send reset, and synchronize with its stopped state."""
        response = self.command(b"!", timeout=timeout)
        if response != b"OK":
            raise RSPProtocolError("server rejected extended remote mode: %r" % response)
        self.send_packet(b"R0", timeout=timeout)
        stop_reply = self.command(b"?", timeout=timeout)
        if not stop_reply.startswith(b"T"):
            raise RSPProtocolError("reset did not produce a stop reply: %r" % stop_reply)

    @staticmethod
    def _checksum(payload: bytes) -> bytes:
        return ("%02x" % (sum(payload) % 256)).encode("ascii")

    @staticmethod
    def _escape_binary(data: bytes) -> bytes:
        escaped = bytearray()
        for value in data:
            if value in (ord("#"), ord("$"), ord("}"), ord("*")):
                escaped.append(ord("}"))
                escaped.append(value ^ 0x20)
            else:
                escaped.append(value)
        return bytes(escaped)

    @staticmethod
    def _unescape_binary(data: bytes) -> bytes:
        unescaped = bytearray()
        index = 0
        while index < len(data):
            value = data[index]
            if value == ord("}"):
                index += 1
                if index >= len(data):
                    raise RSPProtocolError("truncated RSP escape sequence")
                value = data[index] ^ 0x20
            unescaped.append(value)
            index += 1
        return bytes(unescaped)

    def _deadline(self, timeout: Optional[float]) -> float:
        operation_timeout = self._timeout if timeout is None else timeout
        return time.monotonic() + operation_timeout

    def _send(self, data: bytes, deadline: float) -> None:
        self._set_socket_timeout(deadline)
        try:
            self._connection.sendall(data)
        except socket.timeout as error:
            raise RSPTimeoutError("timed out sending RSP data") from error
        except OSError as error:
            self._closed = True
            raise RSPConnectionClosedError("failed to send RSP data") from error

    def _receive_acknowledgement(self, deadline: float) -> bytes:
        while True:
            value = self._receive_byte(deadline)
            if value in (b"+", b"-"):
                return value
            if value == b"\x03":
                self._observe_packet(RSPPacket(time.monotonic(), "receive", "interrupt", value))
                continue
            if value in (b"$", b"%"):
                self._receive_buffer[:0] = value
                self._pending_packets.append(self._receive_packet_from_wire(deadline))
                continue
            raise RSPProtocolError("expected RSP acknowledgement, received %r" % value)

    def _take_pending_response(self) -> Optional[RSPPacket]:
        """Remove and return a deferred ordinary reply, if one is available."""
        for index, packet in enumerate(self._pending_packets):
            if packet.packet_type == "$":
                return self._pending_packets.pop(index)
        return None

    def _receive_byte(self, deadline: float) -> bytes:
        while not self._receive_buffer:
            self._receive_more(deadline)
        value = bytes(self._receive_buffer[:1])
        del self._receive_buffer[:1]
        return value

    def _receive_more(self, deadline: float) -> None:
        self._set_socket_timeout(deadline)
        try:
            data = self._connection.recv(4096)
        except socket.timeout as error:
            raise RSPTimeoutError("timed out waiting for RSP data") from error
        except OSError as error:
            self._closed = True
            raise RSPConnectionClosedError("failed to receive RSP data") from error

        if not data:
            self._closed = True
            raise RSPConnectionClosedError("RSP server closed the connection")
        self._receive_buffer.extend(data)

    def _find_packet_start(self) -> Optional[int]:
        packet_starts = [self._receive_buffer.find(marker) for marker in (b"$", b"%")]
        packet_starts = [index for index in packet_starts if index >= 0]
        return min(packet_starts) if packet_starts else None

    def _set_socket_timeout(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RSPTimeoutError("RSP operation reached its deadline")
        self._connection.settimeout(remaining)

    def _observe_packet(self, packet: RSPPacket) -> None:
        if self._packet_observer is not None:
            self._packet_observer(packet)

# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Deterministic TCP stream collector for gdbserver side channels."""

from __future__ import annotations

import socket
import time
from typing import Callable, Optional


class TCPStreamError(RuntimeError):
    """Base error for a gdbserver TCP stream connection."""


class TCPStreamConnectionError(TCPStreamError):
    """Raised when a stream server cannot be reached."""


class TCPStreamTimeoutError(TCPStreamError):
    """Raised when a stream operation reaches its deadline."""


StreamObserver = Callable[[bytes], None]


class TCPStreamClient:
    """Collect bytes from a local RTT, semihosting, or SWV TCP endpoint."""

    def __init__(self, connection: socket.socket,
                 data_observer: Optional[StreamObserver] = None) -> None:
        self._connection = connection
        self._data_observer = data_observer
        self._received = bytearray()
        self._closed = False

    @classmethod
    def connect(cls, host: str, port: int, timeout: float = 5.0,
                data_observer: Optional[StreamObserver] = None) -> "TCPStreamClient":
        """Connect, retrying while pyOCD creates the requested stream endpoint."""
        deadline = time.monotonic() + timeout
        last_error: Optional[OSError] = None
        while True:
            try:
                connection = socket.create_connection(
                    (host, port),
                    timeout=max(0.001, deadline - time.monotonic()))
                return cls(connection, data_observer=data_observer)
            except OSError as error:
                last_error = error
                if time.monotonic() >= deadline:
                    raise TCPStreamConnectionError(
                        "could not connect to TCP stream %s:%d" % (host, port)) from last_error
                time.sleep(min(0.050, max(0.001, deadline - time.monotonic())))

    @property
    def received(self) -> bytes:
        """All bytes captured from the stream connection so far."""
        return bytes(self._received)

    def close(self) -> None:
        """Close the stream connection."""
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._connection.close()

    def __enter__(self) -> "TCPStreamClient":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def send(self, data: bytes, timeout: float = 5.0) -> None:
        """Send bytes to a bidirectional stream such as an RTT channel."""
        if self._closed:
            raise TCPStreamConnectionError("TCP stream connection is closed")
        self._set_timeout(time.monotonic() + timeout)
        try:
            self._connection.sendall(data)
        except socket.timeout as error:
            raise TCPStreamTimeoutError("timed out sending TCP stream data") from error
        except OSError as error:
            self._closed = True
            raise TCPStreamConnectionError("failed to send TCP stream data") from error

    def read_until(self, expected: bytes, timeout: float = 5.0) -> bytes:
        """Read until the cumulative capture contains ``expected``."""
        if not expected:
            raise ValueError("expected stream marker must not be empty")
        deadline = time.monotonic() + timeout
        while expected not in self._received:
            self._receive_more(deadline)
        return self.received

    def read_available(self, timeout: float = 0.050) -> bytes:
        """Read one available chunk, returning no bytes when the stream is quiet."""
        before = len(self._received)
        try:
            self._receive_more(time.monotonic() + timeout)
        except TCPStreamTimeoutError:
            return b""
        return bytes(self._received[before:])

    def _receive_more(self, deadline: float) -> None:
        if self._closed:
            raise TCPStreamConnectionError("TCP stream connection is closed")
        self._set_timeout(deadline)
        try:
            data = self._connection.recv(4096)
        except socket.timeout as error:
            raise TCPStreamTimeoutError("timed out waiting for TCP stream data") from error
        except OSError as error:
            self._closed = True
            raise TCPStreamConnectionError("failed to receive TCP stream data") from error
        if not data:
            self._closed = True
            raise TCPStreamConnectionError("TCP stream server closed the connection")
        self._received.extend(data)
        if self._data_observer is not None:
            self._data_observer(data)

    def _set_timeout(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TCPStreamTimeoutError("TCP stream operation reached its deadline")
        self._connection.settimeout(remaining)

# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Explicitly gated GDB flash-protocol scenario for any supported test target."""

from __future__ import annotations

import pytest

from pyocd_server import PyOCDGDBServer


_FLASH_DATA = b"pyOCD gdbserver flash #$}* fixture"
_FLASH_GUARD_SIZE = 16


def test_vflash_programs_only_the_user_declared_scratch_region(
        gdbserver_flash_scratch: tuple[int, int],
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that debugger flash programming works only inside the explicitly reserved scratch area and leaves it erased afterwards.
    Test method:
    1. Require an explicitly supplied scratch address and size large enough for the fixed binary payload and an erased guard.
    2. Connect one RSP client and encode vFlashErase and escaped vFlashWrite requests for only that region.
    3. Erase the scratch range, write bytes containing every RSP escape character, and complete with vFlashDone.
    4. Read target flash through RSP, require byte-for-byte payload equality, and verify that vFlashWrite did not alter the following guard.
    5. In finally cleanup, erase and finish the same region even if programming failed after the first erase.
    6. Read back erased bytes and require 0xff throughout the tested payload and guard range.
    Expected result: Each flash packet returns OK, readback equals the payload, the guard remains erased, and cleanup reads as erased bytes.
    Failure indicates: Flash protocol behavior or cleanup is unsafe or inconsistent.
    Skip: No explicit sufficiently large scratch address and size were supplied.
    """
    address, size = gdbserver_flash_scratch
    tested_size = len(_FLASH_DATA) + _FLASH_GUARD_SIZE
    if size < tested_size:
        pytest.skip("declared flash scratch region is too small for the %d-byte payload and guard" % tested_size)

    with gdbserver_server.connect_rsp() as client:
        erase = ("vFlashErase:%x,%x" % (address, size)).encode("ascii")
        write = ("vFlashWrite:%x:" % address).encode("ascii") + _escape_binary(_FLASH_DATA)
        cleanup_required = False
        primary_failure = False
        try:
            assert client.command(erase, timeout=10.0) == b"OK"
            # A vFlashWrite or vFlashDone failure can still leave data in the
            # reserved sector, so schedule cleanup as soon as erase succeeds.
            cleanup_required = True
            assert client.command(write, timeout=10.0) == b"OK"
            assert client.command(b"vFlashDone", timeout=60.0) == b"OK"
            assert client.read_memory(address, len(_FLASH_DATA), timeout=10.0) == _FLASH_DATA
            assert client.read_memory(address + len(_FLASH_DATA), _FLASH_GUARD_SIZE, timeout=10.0) == (
                    b"\xff" * _FLASH_GUARD_SIZE)
        except BaseException:
            primary_failure = True
            raise
        finally:
            # Do not leave the user-reserved scratch region programmed after a
            # successful erase, even when a write or done operation failed.
            # The caller owns the region's alignment and erase granularity.
            if cleanup_required:
                try:
                    assert client.command(erase, timeout=10.0) == b"OK"
                    assert client.command(b"vFlashDone", timeout=60.0) == b"OK"
                    assert client.read_memory(address, tested_size, timeout=10.0) == (
                        b"\xff" * tested_size)
                except Exception:
                    if not primary_failure:
                        raise


def _escape_binary(data: bytes) -> bytes:
    """Escape the RSP payload bytes that are special to a vFlashWrite packet."""
    escaped = bytearray()
    for value in data:
        if value in (ord("#"), ord("$"), ord("}"), ord("*")):
            escaped.append(ord("}"))
            escaped.append(value ^ 0x20)
        else:
            escaped.append(value)
    return bytes(escaped)

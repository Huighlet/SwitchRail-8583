"""
Unit tests for the ISO 8583 Bitmap bitmask encoder and decoder.
"""

import pytest

from switchrail.bitmap import Bitmap
from switchrail.types import BitmapError


def test_primary_bitmap_binary():
    """Verify primary 64-bit bitmap serialization (8 bytes)."""
    # Active fields: 2, 3, 4, 11, 41
    bm = Bitmap([2, 3, 4, 11, 41])
    assert bm.has_secondary is False
    assert bm.is_set(2) is True
    assert bm.is_set(3) is True
    assert bm.is_set(4) is True
    assert bm.is_set(11) is True
    assert bm.is_set(41) is True
    assert bm.is_set(12) is False

    raw_bytes = bm.to_bytes(is_binary=True)
    assert len(raw_bytes) == 8

    # Unpack and verify
    unpacked_bm, consumed = Bitmap.from_bytes(raw_bytes, offset=0, is_binary=True)
    assert consumed == 8
    assert unpacked_bm.get_active_fields() == [2, 3, 4, 11, 41]


def test_secondary_bitmap_binary_expansion():
    """Verify that adding a field > 64 automatically engages Bit 1 and secondary bitmap (16 bytes)."""
    # Active fields: 3, 4, 70, 102
    bm = Bitmap([3, 4, 70, 102])
    assert bm.has_secondary is True

    raw_bytes = bm.to_bytes(is_binary=True)
    assert len(raw_bytes) == 16

    # Bit 1 must be set in first byte
    assert bool(raw_bytes[0] & 0x80) is True

    unpacked_bm, consumed = Bitmap.from_bytes(raw_bytes, offset=0, is_binary=True)
    assert consumed == 16
    assert unpacked_bm.get_active_fields() == [3, 4, 70, 102]


def test_bitmap_ascii_hex():
    """Verify ASCII hex bitmap encoding (16 chars for Primary, 32 chars for Secondary)."""
    bm = Bitmap([3, 4, 11])
    hex_bytes = bm.to_bytes(is_binary=False)
    assert len(hex_bytes) == 16

    unpacked_bm, consumed = Bitmap.from_bytes(hex_bytes, offset=0, is_binary=False)
    assert consumed == 16
    assert unpacked_bm.get_active_fields() == [3, 4, 11]

    # With secondary field
    bm.set(90)
    hex_sec_bytes = bm.to_bytes(is_binary=False)
    assert len(hex_sec_bytes) == 32
    unpacked_sec, consumed_sec = Bitmap.from_bytes(hex_sec_bytes, offset=0, is_binary=False)
    assert consumed_sec == 32
    assert unpacked_sec.get_active_fields() == [3, 4, 11, 90]


def test_bitmap_invalid_field_raises():
    """Verify that field bounds [1..128] are enforced."""
    bm = Bitmap()
    with pytest.raises(BitmapError):
        bm.set(0)

    with pytest.raises(BitmapError):
        bm.set(129)

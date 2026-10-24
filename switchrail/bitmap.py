"""
SwitchRail-8583 Bitmap Bitmask Engine.
High-performance bitwise encoding and decoding for Primary (64-bit) and Secondary (128-bit) bitmaps.
"""

from __future__ import annotations

from typing import Iterable, Set

from switchrail.types import BitmapError


class Bitmap:
    """
    ISO 8583 Bitmap representation.
    Supports both 64-bit (Primary) and 128-bit (Extended Secondary) bitmasks.
    """
    __slots__ = ("_fields",)

    def __init__(self, fields: Iterable[int] | None = None) -> None:
        self._fields: Set[int] = set()
        if fields:
            for f in fields:
                self.set(f)

    def set(self, field_number: int) -> None:
        """Mark a field as present in the message."""
        if not (1 <= field_number <= 128):
            raise BitmapError(f"Field number must be between 1 and 128, got {field_number}")
        self._fields.add(field_number)

    def clear(self, field_number: int) -> None:
        """Mark a field as absent."""
        self._fields.discard(field_number)

    def is_set(self, field_number: int) -> bool:
        """Check if a field is present."""
        return field_number in self._fields

    @property
    def has_secondary(self) -> bool:
        """True if any field > 64 is active, necessitating a secondary bitmap."""
        return any(f > 64 for f in self._fields)

    def get_active_fields(self) -> list[int]:
        """Return sorted list of active data element numbers."""
        return sorted(self._fields)

    def to_bytes(self, is_binary: bool = True) -> bytes:
        """
        Encode bitmap into bytes.
        If is_binary=True, produces 8 bytes (Primary) or 16 bytes (Secondary).
        If is_binary=False, produces 16 hex chars (Primary) or 32 hex chars (Secondary) ASCII.
        """
        use_secondary = self.has_secondary
        num_bytes = 16 if use_secondary else 8
        raw_bytes = bytearray(num_bytes)

        # If secondary bitmap is active, Bit 1 of primary bitmap MUST be set to 1
        active = set(self._fields)
        if use_secondary:
            active.add(1)
        else:
            active.discard(1)

        for f in active:
            byte_index = (f - 1) // 8
            bit_index = 7 - ((f - 1) % 8)
            raw_bytes[byte_index] |= (1 << bit_index)

        if is_binary:
            return bytes(raw_bytes)
        else:
            return raw_bytes.hex().upper().encode("ascii")

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0, is_binary: bool = True) -> tuple[Bitmap, int]:
        """
        Parse bitmap from byte stream starting at offset.
        Returns: (Bitmap instance, number of bytes consumed).
        """
        if is_binary:
            if len(data) < offset + 8:
                raise BitmapError("Buffer truncated: expected at least 8 bytes for primary binary bitmap")
            first_byte = data[offset]
            has_secondary = bool(first_byte & 0x80)
            required_len = 16 if has_secondary else 8

            if len(data) < offset + required_len:
                raise BitmapError(
                    f"Buffer truncated: expected {required_len} bytes for binary bitmap, got {len(data) - offset}"
                )

            bitmap_slice = data[offset : offset + required_len]
            consumed = required_len
        else:
            # ASCII hex bitmap
            if len(data) < offset + 16:
                raise BitmapError("Buffer truncated: expected at least 16 hex characters for primary ASCII bitmap")
            first_char = chr(data[offset])
            first_nibble = int(first_char, 16)
            has_secondary = bool(first_nibble & 0x8)
            required_hex_chars = 32 if has_secondary else 16

            if len(data) < offset + required_hex_chars:
                raise BitmapError(
                    f"Buffer truncated: expected {required_hex_chars} hex characters, got {len(data) - offset}"
                )

            hex_slice = data[offset : offset + required_hex_chars].decode("ascii")
            bitmap_slice = bytes.fromhex(hex_slice)
            consumed = required_hex_chars

        fields = set()
        for byte_idx, b in enumerate(bitmap_slice):
            for bit_idx in range(8):
                if b & (1 << (7 - bit_idx)):
                    field_num = (byte_idx * 8) + bit_idx + 1
                    if field_num != 1:  # Bit 1 is only the secondary indicator, not a data field
                        fields.add(field_num)

        return cls(fields=fields), consumed

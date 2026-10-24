"""
SwitchRail-8583 Message Container and Framing Codec.
High-throughput packing, unpacking, field inspection, and automated response/reversal generation.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional

from switchrail.bitmap import Bitmap
from switchrail.fields import ISO8583_SPEC, FieldDefinition
from switchrail.types import PackingError, ResponseCode, UnpackingError


class ISO8583Message:
    """
    Standard ISO 8583 Financial Message.
    Encapsulates MTI, Primary/Secondary Bitmaps, and Data Elements.
    """
    __slots__ = ("mti", "_fields", "is_binary_bitmap")

    def __init__(self, mti: str = "0200", is_binary_bitmap: bool = True) -> None:
        self.mti = mti
        self._fields: Dict[int, str] = {}
        self.is_binary_bitmap = is_binary_bitmap

    def set(self, field_number: int, value: Any) -> ISO8583Message:
        """Assign value to a specific data element (DE)."""
        if field_number not in ISO8583_SPEC:
            raise PackingError(f"Field {field_number} is not defined in ISO 8583 specification.")
        self._fields[field_number] = str(value)
        return self

    def get(self, field_number: int, default: Optional[str] = None) -> Optional[str]:
        """Retrieve value of data element."""
        return self._fields.get(field_number, default)

    def has(self, field_number: int) -> bool:
        """Check if data element exists."""
        return field_number in self._fields

    def delete(self, field_number: int) -> None:
        """Remove data element."""
        self._fields.pop(field_number, None)

    @property
    def fields(self) -> Dict[int, str]:
        """Return dictionary of present data elements."""
        return dict(self._fields)

    def pack(self, include_length_prefix: bool = True) -> bytes:
        """
        Serialize ISO 8583 message into wire-format bytes.
        Structure: [2-Byte Length Header] + [4-Byte MTI] + [Bitmap] + [Packed Data Elements]
        """
        if len(self.mti) != 4 or not self.mti.isdigit():
            raise PackingError(f"Invalid MTI: '{self.mti}', expected 4 numeric digits.")

        # 1. Encode MTI
        mti_bytes = self.mti.encode("ascii")

        # 2. Build and encode Bitmap
        bitmap = Bitmap(fields=self._fields.keys())
        bitmap_bytes = bitmap.to_bytes(is_binary=self.is_binary_bitmap)

        # 3. Encode Data Elements in sequential ascending order
        elements_bytes = bytearray()
        for field_num in bitmap.get_active_fields():
            spec = ISO8583_SPEC[field_num]
            val = self._fields[field_num]
            packed_val = spec.pack(val)
            elements_bytes.extend(packed_val)

        payload = mti_bytes + bitmap_bytes + bytes(elements_bytes)

        if include_length_prefix:
            # 2-byte unsigned big-endian length prefix
            prefix = struct.pack(">H", len(payload))
            return prefix + payload
        else:
            return payload

    @classmethod
    def unpack(
        cls,
        data: bytes,
        has_length_prefix: bool = True,
        is_binary_bitmap: bool = True,
    ) -> ISO8583Message:
        """
        Deserialize wire-format bytes into ISO8583Message instance.
        """
        offset = 0

        if has_length_prefix:
            if len(data) < 2:
                raise UnpackingError("Data buffer too short for 2-byte network length header")
            (expected_len,) = struct.unpack(">H", data[0:2])
            offset = 2
            if len(data) < offset + expected_len:
                raise UnpackingError(
                    f"Message truncated: expected {expected_len} bytes from length header, got {len(data) - offset}"
                )

        # 1. Extract 4-byte MTI
        if len(data) < offset + 4:
            raise UnpackingError("Data buffer too short for 4-byte MTI")
        mti = data[offset : offset + 4].decode("ascii")
        if not mti.isdigit():
            raise UnpackingError(f"Non-numeric MTI: '{mti}'")
        offset += 4

        # 2. Extract Bitmap
        bitmap, consumed = Bitmap.from_bytes(data, offset=offset, is_binary=is_binary_bitmap)
        offset += consumed

        # 3. Extract Data Elements
        msg = cls(mti=mti, is_binary_bitmap=is_binary_bitmap)
        for field_num in bitmap.get_active_fields():
            if field_num not in ISO8583_SPEC:
                raise UnpackingError(f"Encountered unknown active field {field_num} in bitmap")
            spec = ISO8583_SPEC[field_num]
            val, field_consumed = spec.unpack(data, offset)
            msg.set(field_num, val)
            offset += field_consumed

        return msg

    def build_response(self, response_code: str = ResponseCode.APPROVED) -> ISO8583Message:
        """
        Construct a mirrored ISO 8583 response message:
          0100 -> 0110, 0200 -> 0210, 0420 -> 0430, 0800 -> 0810.
        """
        mti_int = int(self.mti)
        resp_mti = f"{mti_int + 10:04d}"

        resp = ISO8583Message(mti=resp_mti, is_binary_bitmap=self.is_binary_bitmap)

        # Propagate audit and routing identifiers
        for f in (2, 3, 4, 7, 11, 12, 13, 14, 18, 22, 25, 32, 37, 41, 42, 49, 70, 102, 103):
            if self.has(f):
                resp.set(f, self.get(f))

        # Set Response Code (DE 39)
        resp.set(39, response_code)

        # If approved, generate authorization code (DE 38)
        if response_code == ResponseCode.APPROVED and not resp.has(38):
            stan = self.get(11, "000000")
            auth_code = f"A{stan[-5:]}" if len(stan) >= 5 else "AUTH01"
            resp.set(38, auth_code[:6])

        return resp

    def build_reversal(self, reason_code: str = ResponseCode.TIMEOUT_REVERSAL) -> ISO8583Message:
        """
        Generate an Acquirer Reversal Advice (0420) from an unconfirmed 0200 financial request.
        Embeds Original Data Elements (DE 90).
        """
        rev = ISO8583Message(mti="0420", is_binary_bitmap=self.is_binary_bitmap)

        # Copy original financial parameters
        for f in (2, 3, 4, 11, 12, 13, 22, 25, 32, 37, 41, 42, 49, 102, 103):
            if self.has(f):
                rev.set(f, self.get(f))

        # Build DE 90: Original Data Elements (42 digits):
        # [0:4] Original MTI (4)
        # [4:10] Original STAN (6)
        # [10:20] Original Transmission Date & Time (10)
        # [20:31] Original Acquiring Inst ID Code (11, zero-padded left)
        # [31:42] Forwarding Inst ID Code (11, zero-padded left)
        orig_mti = self.mti.zfill(4)
        orig_stan = (self.get(11) or "000000").zfill(6)
        orig_dt = (self.get(7) or "0000000000").zfill(10)
        orig_acq = (self.get(32) or "00000000000").zfill(11)
        orig_fwd = "00000000000"
        de_90 = f"{orig_mti}{orig_stan}{orig_dt}{orig_acq}{orig_fwd}"[:42]

        rev.set(90, de_90)
        rev.set(39, reason_code)
        return rev

    def dump(self) -> str:
        """Produce a structured ASCII table of message contents."""
        lines = [
            f"=== ISO 8583 Message [MTI: {self.mti}] ===",
            f"Bitmap Format: {'Binary (8/16 bytes)' if self.is_binary_bitmap else 'ASCII Hex (16/32 chars)'}",
            f"{'DE':<5} | {'Field Name':<35} | {'Value'}",
            "-" * 65,
        ]
        for f in sorted(self._fields.keys()):
            spec = ISO8583_SPEC.get(f)
            name = spec.name if spec else f"Unknown Field {f}"
            val = self._fields[f]
            # Mask sensitive PAN in dump
            if f == 2 and len(val) >= 10:
                masked_val = f"{val[:6]}{'*' * (len(val) - 10)}{val[-4:]}"
            else:
                masked_val = val
            lines.append(f"{f:<5} | {name:<35} | {masked_val}")
        lines.append("=" * 65)
        return "\n".join(lines)

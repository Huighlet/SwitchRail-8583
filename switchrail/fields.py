"""
SwitchRail-8583 Data Element Definitions and Serialization Engine.
Encodes and decodes ISO 8583 Data Elements (DE 2 to DE 128) with strict padding and length prefix checks.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, Tuple

from switchrail.types import FieldType, PackingError, UnpackingError


@dataclasses.dataclass(slots=True, frozen=True)
class FieldDefinition:
    """Specification of an individual ISO 8583 Data Element."""
    number: int
    name: str
    field_type: FieldType
    max_length: int

    def pack(self, value: str | bytes) -> bytes:
        """Serialize a field value according to its ISO 8583 type specification."""
        if isinstance(value, bytes):
            str_val = value.decode("latin1")
        else:
            str_val = str(value)

        # 1. Fixed Numeric: Left zero-padded
        if self.field_type == FieldType.NUMERIC:
            if not str_val.isdigit():
                raise PackingError(f"Field {self.number} ({self.name}) requires numeric value, got '{str_val}'")
            if len(str_val) > self.max_length:
                raise PackingError(f"Field {self.number} exceeds max length {self.max_length}: '{str_val}'")
            padded = str_val.zfill(self.max_length)
            return padded.encode("latin1")

        # 2. Fixed Alphanumeric / Alpha / Special: Right space-padded
        elif self.field_type in (FieldType.ALPHA, FieldType.ALPHANUMERIC, FieldType.ALPHANUMERIC_SPECIAL):
            if len(str_val) > self.max_length:
                raise PackingError(f"Field {self.number} exceeds max length {self.max_length}: '{str_val}'")
            padded = str_val.ljust(self.max_length)
            return padded.encode("latin1")

        # 3. LLVAR (Variable length, 2-digit length prefix: 00-99)
        elif self.field_type in (FieldType.LLVAR_NUMERIC, FieldType.LLVAR_ALPHA):
            if len(str_val) > self.max_length:
                raise PackingError(f"Field {self.number} exceeds max length {self.max_length}: '{str_val}'")
            length_prefix = f"{len(str_val):02d}"
            return (length_prefix + str_val).encode("latin1")

        # 4. LLLVAR (Variable length, 3-digit length prefix: 000-999)
        elif self.field_type in (FieldType.LLLVAR_ALPHA, FieldType.LLLVAR_BINARY):
            if len(str_val) > self.max_length:
                raise PackingError(f"Field {self.number} exceeds max length {self.max_length}: '{str_val}'")
            length_prefix = f"{len(str_val):03d}"
            return (length_prefix + str_val).encode("latin1")

        # 5. Fixed Binary: Hex string representation
        elif self.field_type == FieldType.BINARY:
            if len(str_val) != self.max_length * 2 and len(str_val) != self.max_length:
                # Accept either hex string or direct raw byte representation
                raise PackingError(f"Field {self.number} binary length mismatch: expected {self.max_length} bytes")
            return str_val.encode("latin1")

        raise PackingError(f"Unsupported field type {self.field_type} for field {self.number}")

    def unpack(self, data: bytes, offset: int) -> Tuple[str, int]:
        """
        Deserialize field from byte stream starting at offset.
        Returns: (extracted_value_str, bytes_consumed).
        """
        # 1. Fixed Length Fields
        if self.field_type in (FieldType.NUMERIC, FieldType.ALPHA, FieldType.ALPHANUMERIC, FieldType.ALPHANUMERIC_SPECIAL):
            required = self.max_length
            if len(data) < offset + required:
                raise UnpackingError(
                    f"Truncated buffer for field {self.number} ({self.name}): "
                    f"expected {required} bytes, got {len(data) - offset}"
                )
            raw = data[offset : offset + required].decode("latin1")
            return raw, required

        # 2. LLVAR Fields (2-digit length prefix)
        elif self.field_type in (FieldType.LLVAR_NUMERIC, FieldType.LLVAR_ALPHA):
            if len(data) < offset + 2:
                raise UnpackingError(f"Truncated buffer reading LLVAR prefix for field {self.number}")
            prefix_str = data[offset : offset + 2].decode("latin1")
            if not prefix_str.isdigit():
                raise UnpackingError(f"Invalid non-numeric LLVAR prefix for field {self.number}: '{prefix_str}'")
            length = int(prefix_str)
            if length > self.max_length:
                raise UnpackingError(f"Field {self.number} LLVAR length {length} exceeds maximum {self.max_length}")
            if len(data) < offset + 2 + length:
                raise UnpackingError(f"Truncated buffer for LLVAR field {self.number}: expected {length} bytes")
            raw = data[offset + 2 : offset + 2 + length].decode("latin1")
            return raw, 2 + length

        # 3. LLLVAR Fields (3-digit length prefix)
        elif self.field_type in (FieldType.LLLVAR_ALPHA, FieldType.LLLVAR_BINARY):
            if len(data) < offset + 3:
                raise UnpackingError(f"Truncated buffer reading LLLVAR prefix for field {self.number}")
            prefix_str = data[offset : offset + 3].decode("latin1")
            if not prefix_str.isdigit():
                raise UnpackingError(f"Invalid non-numeric LLLVAR prefix for field {self.number}: '{prefix_str}'")
            length = int(prefix_str)
            if length > self.max_length:
                raise UnpackingError(f"Field {self.number} LLLVAR length {length} exceeds maximum {self.max_length}")
            if len(data) < offset + 3 + length:
                raise UnpackingError(f"Truncated buffer for LLLVAR field {self.number}: expected {length} bytes")
            raw = data[offset + 3 : offset + 3 + length].decode("latin1")
            return raw, 3 + length

        # 4. Fixed Binary Field
        elif self.field_type == FieldType.BINARY:
            required = self.max_length
            if len(data) < offset + required:
                raise UnpackingError(f"Truncated buffer for binary field {self.number}")
            raw = data[offset : offset + required].decode("latin1")
            return raw, required

        raise UnpackingError(f"Unsupported field type {self.field_type} for field {self.number}")


# -------------------------------------------------------------------------
# Standard ISO 8583:1987 Field Catalog
# -------------------------------------------------------------------------

ISO8583_SPEC: Dict[int, FieldDefinition] = {
    2: FieldDefinition(2, "Primary Account Number (PAN)", FieldType.LLVAR_NUMERIC, 19),
    3: FieldDefinition(3, "Processing Code", FieldType.NUMERIC, 6),
    4: FieldDefinition(4, "Amount, Transaction", FieldType.NUMERIC, 12),
    7: FieldDefinition(7, "Transmission Date & Time", FieldType.NUMERIC, 10),
    11: FieldDefinition(11, "Systems Trace Audit Number (STAN)", FieldType.NUMERIC, 6),
    12: FieldDefinition(12, "Time, Local Transaction", FieldType.NUMERIC, 6),
    13: FieldDefinition(13, "Date, Local Transaction", FieldType.NUMERIC, 4),
    14: FieldDefinition(14, "Date, Expiration", FieldType.NUMERIC, 4),
    18: FieldDefinition(18, "Merchant Category Code (MCC)", FieldType.NUMERIC, 4),
    22: FieldDefinition(22, "Point of Service Entry Mode", FieldType.NUMERIC, 3),
    25: FieldDefinition(25, "Point of Service Condition Code", FieldType.NUMERIC, 2),
    32: FieldDefinition(32, "Acquiring Institution ID Code", FieldType.LLVAR_NUMERIC, 11),
    37: FieldDefinition(37, "Retrieval Reference Number (RRN)", FieldType.ALPHANUMERIC, 12),
    38: FieldDefinition(38, "Authorization ID Response", FieldType.ALPHANUMERIC, 6),
    39: FieldDefinition(39, "Response Code", FieldType.ALPHANUMERIC, 2),
    41: FieldDefinition(41, "Card Acceptor Terminal ID (TID)", FieldType.ALPHANUMERIC_SPECIAL, 8),
    42: FieldDefinition(42, "Card Acceptor ID Code (MID)", FieldType.ALPHANUMERIC_SPECIAL, 15),
    43: FieldDefinition(43, "Card Acceptor Name/Location", FieldType.ALPHANUMERIC_SPECIAL, 40),
    48: FieldDefinition(48, "Additional Data - Private", FieldType.LLLVAR_ALPHA, 999),
    49: FieldDefinition(49, "Currency Code, Transaction", FieldType.NUMERIC, 3),
    54: FieldDefinition(54, "Additional Amounts", FieldType.LLLVAR_ALPHA, 120),
    70: FieldDefinition(70, "Network Management Info Code", FieldType.NUMERIC, 3),
    90: FieldDefinition(90, "Original Data Elements (Reversals)", FieldType.NUMERIC, 42),
    102: FieldDefinition(102, "Account Identification 1 (Source)", FieldType.LLVAR_ALPHA, 28),
    103: FieldDefinition(103, "Account Identification 2 (Dest)", FieldType.LLVAR_ALPHA, 28),
    128: FieldDefinition(128, "Message Authentication Code (MAC)", FieldType.BINARY, 16),
}

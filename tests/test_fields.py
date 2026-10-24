"""
Unit tests for ISO 8583 Data Element padding, packing, and length prefix validations.
"""

import pytest

from switchrail.fields import ISO8583_SPEC, FieldDefinition, FieldType
from switchrail.types import PackingError, UnpackingError


def test_numeric_field_zero_padded():
    """Verify DE 4 (Amount, length 12) zero-padding behavior."""
    field_def = ISO8583_SPEC[4]
    packed = field_def.pack("50000")
    assert packed == b"000000050000"
    assert len(packed) == 12

    val, consumed = field_def.unpack(packed, 0)
    assert val == "000000050000"
    assert consumed == 12


def test_alphanumeric_field_space_padded():
    """Verify DE 41 (TID, length 8) space-padding behavior."""
    field_def = ISO8583_SPEC[41]
    packed = field_def.pack("ATM01")
    assert packed == b"ATM01   "
    assert len(packed) == 8

    val, consumed = field_def.unpack(packed, 0)
    assert val == "ATM01   "
    assert consumed == 8


def test_llvar_numeric_field():
    """Verify DE 2 (PAN, LLVAR) 2-digit length prefixing."""
    field_def = ISO8583_SPEC[2]
    pan = "4143451234567890"  # 16 digits
    packed = field_def.pack(pan)
    assert packed == b"164143451234567890"

    val, consumed = field_def.unpack(packed, 0)
    assert val == pan
    assert consumed == 2 + 16


def test_lllvar_alpha_field():
    """Verify DE 48 (Private data, LLLVAR) 3-digit length prefixing."""
    field_def = ISO8583_SPEC[48]
    data = "MOBILE_MONEY_TOKEN=MOMO_GH_12345"
    packed = field_def.pack(data)
    expected_prefix = f"{len(data):03d}".encode("latin1")
    assert packed.startswith(expected_prefix)

    val, consumed = field_def.unpack(packed, 0)
    assert val == data
    assert consumed == 3 + len(data)


def test_field_length_overflow_raises():
    """Verify that exceeding field max length raises PackingError."""
    field_def = ISO8583_SPEC[11]  # STAN, length 6
    with pytest.raises(PackingError):
        field_def.pack("1234567")  # 7 digits


def test_numeric_field_non_numeric_raises():
    """Verify that non-numeric characters in NUMERIC field raise PackingError."""
    field_def = ISO8583_SPEC[3]  # Processing Code, length 6
    with pytest.raises(PackingError):
        field_def.pack("00A000")

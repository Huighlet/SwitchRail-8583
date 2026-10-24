"""
Unit tests for ISO8583Message roundtrip packing, unpacking, response, and reversal generation.
"""

import pytest

from switchrail.message import ISO8583Message
from switchrail.types import NetworkManagementCode, ResponseCode


def test_0800_echo_test_roundtrip():
    """Verify pack and unpack for 0800 Network Management message."""
    msg = ISO8583Message(mti="0800", is_binary_bitmap=True)
    msg.set(7, "1024063000")
    msg.set(11, "000001")
    msg.set(70, NetworkManagementCode.ECHO_TEST)

    wire_bytes = msg.pack(include_length_prefix=True)
    unpacked = ISO8583Message.unpack(wire_bytes, has_length_prefix=True, is_binary_bitmap=True)

    assert unpacked.mti == "0800"
    assert unpacked.get(7) == "1024063000"
    assert unpacked.get(11) == "000001"
    assert unpacked.get(70) == "301"

    # Test auto response generation (0800 -> 0810)
    resp = unpacked.build_response(ResponseCode.APPROVED)
    assert resp.mti == "0810"
    assert resp.get(39) == "00"
    assert resp.get(70) == "301"


def test_0200_financial_purchase_roundtrip():
    """Verify full financial transaction 0200 message with secondary bitmap (DE 102)."""
    msg = ISO8583Message(mti="0200", is_binary_bitmap=True)
    msg.set(2, "5399831122334455")        # Stanbic PAN
    msg.set(3, "000000")                  # Purchase
    msg.set(4, "000000100000")            # 1,000.00 GHS
    msg.set(7, "1024063500")
    msg.set(11, "123456")
    msg.set(37, "202610240001")
    msg.set(41, "POS_ACC1")
    msg.set(49, "936")
    msg.set(102, "ACC_SENDER_WALLET")     # Field > 64 triggers secondary bitmap

    wire_bytes = msg.pack(include_length_prefix=True)
    unpacked = ISO8583Message.unpack(wire_bytes, has_length_prefix=True, is_binary_bitmap=True)

    assert unpacked.mti == "0200"
    assert unpacked.get(2) == "5399831122334455"
    assert unpacked.get(3) == "000000"
    assert unpacked.get(4) == "000000100000"
    assert unpacked.get(11) == "123456"
    assert unpacked.get(37) == "202610240001"
    assert unpacked.get(102) == "ACC_SENDER_WALLET"

    # Test response generation (0200 -> 0210)
    resp = unpacked.build_response(ResponseCode.APPROVED)
    assert resp.mti == "0210"
    assert resp.get(39) == "00"
    assert resp.has(38) is True  # Authorization code generated
    assert resp.get(2) == "5399831122334455"


def test_reversal_generation_embeds_de90():
    """Verify that build_reversal() accurately constructs 0420 with DE 90 Original Data Elements."""
    msg = ISO8583Message(mti="0200", is_binary_bitmap=True)
    msg.set(2, "4143459988776655")
    msg.set(3, "010000")                  # ATM Cash Withdrawal
    msg.set(4, "000000020000")            # 200.00 GHS
    msg.set(7, "1024064000")
    msg.set(11, "000999")
    msg.set(32, "414345")
    msg.set(41, "ATM_KOTOKA")

    reversal = msg.build_reversal(reason_code=ResponseCode.TIMEOUT_REVERSAL)
    assert reversal.mti == "0420"
    assert reversal.get(39) == "91"
    assert reversal.has(90) is True

    de_90 = reversal.get(90)
    assert len(de_90) == 42
    # Verify DE 90 contains original MTI 0200 and STAN 000999
    assert de_90.startswith("02000009991024064000")


def test_message_dump_masks_pan():
    """Verify that dump() shields sensitive cardholder primary account numbers."""
    msg = ISO8583Message(mti="0200")
    msg.set(2, "4143451234567890")
    msg.set(4, "000000010000")

    dump_str = msg.dump()
    assert "414345******7890" in dump_str
    assert "4143451234567890" not in dump_str

"""
SwitchRail-8583: Core Types, Field Encodings, and ISO 8583 Protocol Exceptions.
"""

from __future__ import annotations

import enum


class FieldType(enum.Enum):
    """
    Standard ISO 8583 data element formatting types.
    """
    NUMERIC = "n"                     # Fixed numeric, zero-padded left
    ALPHA = "a"                       # Fixed alphabetic, space-padded right
    ALPHANUMERIC = "an"               # Fixed alphanumeric, space-padded right
    ALPHANUMERIC_SPECIAL = "ans"      # Fixed alphanumeric + special chars, space-padded right
    BINARY = "b"                      # Fixed raw binary bytes / bitmask
    LLVAR_NUMERIC = "LLVAR_n"         # 2-digit length prefix + numeric string
    LLVAR_ALPHA = "LLVAR_an"          # 2-digit length prefix + alphanumeric string
    LLLVAR_ALPHA = "LLLVAR_ans"       # 3-digit length prefix + alphanumeric string
    LLLVAR_BINARY = "LLLVAR_b"        # 3-digit length prefix + binary hex string


class ResponseCode(enum.StrEnum):
    """Standard ISO 8583 Field 39 Response Codes."""
    APPROVED = "00"
    REFER_TO_ISSUER = "01"
    DO_NOT_HONOR = "05"
    INVALID_TRANSACTION = "12"
    INVALID_AMOUNT = "13"
    INVALID_CARD_NUMBER = "14"
    FORMAT_ERROR = "30"
    LOST_CARD = "41"
    STOLEN_CARD = "43"
    INSUFFICIENT_FUNDS = "51"
    EXPIRED_CARD = "54"
    INCORRECT_PIN = "55"
    TRANSACTION_NOT_PERMITTED = "57"
    SUSPECTED_FRAUD = "59"
    RESTRICTED_CARD = "62"
    PIN_TRIES_EXCEEDED = "75"
    SYSTEM_MALFUNCTION = "96"
    TIMEOUT_REVERSAL = "91"


class NetworkManagementCode(enum.StrEnum):
    """Standard ISO 8583 Field 70 Network Codes."""
    LOGON = "001"
    LOGOFF = "002"
    ECHO_TEST = "301"
    KEY_EXCHANGE = "101"


# -------------------------------------------------------------------------
# Exceptions
# -------------------------------------------------------------------------

class ISO8583Error(Exception):
    """Base exception for all SwitchRail ISO 8583 processing errors."""


class BitmapError(ISO8583Error):
    """Raised when bitmap encoding or decoding fails."""


class PackingError(ISO8583Error):
    """Raised when an ISO 8583 message fails binary or ASCII serialization."""


class UnpackingError(ISO8583Error):
    """Raised when a stream cannot be parsed into a valid ISO 8583 message."""


class RoutingError(ISO8583Error):
    """Raised when no valid destination route exists for an incoming transaction."""


class SwitchTimeoutError(ISO8583Error):
    """Raised when an upstream issuer bank fails to respond within the SLA deadline."""

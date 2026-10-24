# SwitchRail-8583

High-Performance Financial Protocol Engine, ISO 8583 Parser, and Payment Switch.

Designed for inter-bank card clearing rails, ATM/POS acquirer networks, and national payment switches (such as GhIPSS in Ghana, NIBSS in Nigeria, and global card schemes). Built from first principles to provide zero-allocation bitmask manipulation, dynamic BIN routing, and Store-and-Forward (SAF) reversal guarantees.

---

## 1. Problem Definition: The Limits of REST in Financial Core Switching

Modern web developers frequently assume financial payments operate over JSON/HTTP REST APIs (`POST /api/v1/charge`). However, mission-critical banking rails, ATM networks, POS terminals, and inter-bank clearing houses operate almost exclusively on the **ISO 8583** and **ISO 20022** telecommunications standards over raw TCP/IP sockets.

### Why ISO 8583 Dominates Core Banking

| Constraint | JSON / HTTP REST | ISO 8583 Binary Framing |
| :--- | :--- | :--- |
| **Payload Overhead** | Verbose ASCII key names (`"transaction_amount": 50000`) consuming 1–3 KB per transaction. | Bitmask-indexed binary frames consuming 100–180 bytes per transaction. |
| **Parsing Latency** | String serialization, JSON AST generation, and text parsing introduce millisecond-scale CPU overhead. | Microsecond-scale bitwise shift/mask operations over raw bytes. |
| **Network Reliability** | HTTP keep-alives struggle over constrained telco/GPRS links and satellite connections. | Compact 2-byte big-endian framing over persistent multiplexed TCP streams. |
| **Reversals & Hardware Timeouts** | Ad-hoc webhook retries cause floating funds or double-debits during dropped connections. | Standardized 0420 Store-and-Forward (SAF) Reversals with Original Data Elements (DE 90). |

---

## 2. ISO 8583 Framing Specification

A SwitchRail wire message conforms to the following structural framing:

```
+------------------+---------------+--------------------+--------------------------------+
| Length Header    | MTI           | Bitmask (Bitmap)   | Data Elements (DE 2 .. DE 128) |
| 2 Bytes (Big-End)| 4 ASCII Digits| 8 or 16 Bytes Raw  | Sequential Variable / Fixed    |
+------------------+---------------+--------------------+--------------------------------+
```

### 1. Message Type Identifier (MTI)

Four numeric digits encoding version, class, function, and origin:

| Digit | Meaning | Supported Values |
| :--- | :--- | :--- |
| **Pos 1** | ISO Version | `0` (ISO 8583:1987), `1` (ISO 8583:1993), `2` (ISO 8583:2003) |
| **Pos 2** | Message Class | `1` (Authorization), `2` (Financial), `4` (Reversal), `8` (Network Management) |
| **Pos 3** | Message Function | `0` (Request), `1` (Response), `2` (Advice), `3` (Advice Response) |
| **Pos 4** | Originator | `0` (Acquirer), `1` (Acquirer Repeat), `2` (Issuer) |

Common MTIs supported:
* `0100` / `0110`: Authorization Request / Response
* `0200` / `0210`: Financial Transaction Request (Purchase, Cash Withdrawal) / Response
* `0420` / `0430`: Acquirer Reversal Advice (Dispenser Hardware Failure, Network Timeout) / Acknowledgment
* `0800` / `0810`: Network Management Echo Test / Sign-on Handshake

### 2. The Primary and Secondary Bitmap

- **Primary Bitmap (64 bits):** Bits 1 to 64 represent the presence of Data Elements 1 through 64.
- **Secondary Bitmap Indicator (Bit 1):** If any field between 65 and 128 is present (e.g. Account Identification DE 102/103), Bit 1 is automatically flipped to `1`, extending the bitmap to 128 bits (16 raw bytes or 32 hex characters).

```
PRIMARY BITMAP (64 BITS / 8 BYTES)
Bit 1: Secondary Bitmap Flag (1 = DE 65..128 Present)
Bits 2..64: Active Data Elements
+---+---+---+---+---+---+---+---+--------------------+
| 1 | 2 | 3 | 4 | 7 | 11|...| 64| DE Presence Bitmask|
+---+---+---+---+---+---+---+---+--------------------+
```

---

## 3. Architecture and Data Flow

```
     INBOUND ACQUIRER
 (ATM / POS / Web Terminal)
            |
            v  [Raw TCP Stream with 2-byte Length Header]
 +---------------------------------------------------------------+
 |                       SwitchRail-8583 Engine                  |
 |                                                               |
 |  1. Wire Frame Parser (MTI + Bitmap Unpacker)                 |
 |  2. Dynamic Longest Prefix Match (LPM) BIN Router             |
 |     - 414345 -> Ecobank Ghana                                 |
 |     - 539983 -> Stanbic Bank                                  |
 |     - 504108 -> GCB Bank                                      |
 |     - Default -> GhIPSS Inter-Bank Clearing Switch            |
 |                                                               |
 |  3. Automated Store-and-Forward (SAF) Reversal Coordinator    |
 |     - In-Flight Timeout Detection                             |
 |     - Automatic 0420 Reversal Generation with DE 90           |
 |     - Exponential Backoff Retry Engine                        |
 +---------------------------------------------------------------+
            |                               |
            v                               v
    [ISSUER BANK A]                 [ISSUER BANK B]
```

---

## 4. Supported Data Elements (DE) Catalog

SwitchRail provides strict field formatting and length validations:

| DE | Field Name | Type | Max Len | Formatting / Description |
| :--- | :--- | :--- | :--- | :--- |
| **2** | Primary Account Number (PAN) | `LLVAR_n` | 19 | 2-digit length prefix + card number |
| **3** | Processing Code | `n` | 6 | `000000` (Purchase), `010000` (Withdrawal) |
| **4** | Amount, Transaction | `n` | 12 | 12-digit integer minor units zero-padded left |
| **7** | Transmission Date & Time | `n` | 10 | `MMDDhhmmss` |
| **11** | Systems Trace Audit Number (STAN) | `n` | 6 | Unique monotonic audit sequence |
| **12** | Time, Local Transaction | `n` | 6 | `hhmmss` |
| **13** | Date, Local Transaction | `n` | 4 | `MMDD` |
| **14** | Date, Expiration | `n` | 4 | `YYMM` |
| **18** | Merchant Category Code (MCC) | `n` | 4 | ISO 18245 merchant category |
| **22** | Point of Service Entry Mode | `n` | 3 | Chip, Magnetic Stripe, or Contactless |
| **25** | Point of Service Condition Code | `n` | 2 | Normal or Card-Not-Present |
| **32** | Acquiring Institution ID Code | `LLVAR_n` | 11 | Bank identification code |
| **37** | Retrieval Reference Number (RRN) | `an` | 12 | Unique transaction clearing reference |
| **38** | Authorization ID Response | `an` | 6 | Approval authorization code |
| **39** | Response Code | `an` | 2 | `00` (Approved), `51` (Insufficient Funds), `91` (Timeout) |
| **41** | Card Acceptor Terminal ID (TID) | `ans` | 8 | ATM or POS terminal identifier |
| **42** | Card Acceptor ID Code (MID) | `ans` | 15 | Merchant account number |
| **43** | Card Acceptor Name/Location | `ans` | 40 | Merchant commercial trading name |
| **48** | Additional Data - Private | `LLLVAR_ans` | 999 | Mobile money token / EMV tags |
| **49** | Currency Code, Transaction | `n` | 3 | ISO 4217 numeric (e.g. `936` for GHS, `840` for USD) |
| **70** | Network Management Code | `n` | 3 | `001` (Sign-on), `301` (Echo test) |
| **90** | Original Data Elements | `n` | 42 | Original MTI, STAN, and timestamp for 0420 reversals |
| **102** | Account Identification 1 (Source) | `LLVAR_ans` | 28 | Sender wallet / account identifier |
| **103** | Account Identification 2 (Dest) | `LLVAR_ans` | 28 | Receiver wallet / account identifier |

---

## 5. Performance Benchmarks

Micro-benchmarks executed on commodity 64-bit hardware (Python 3.13):

```text
============================================================
SWITCHRAIL-8583 BENCHMARK: 50,000 MESSAGES
============================================================
Wire Message Size:        175 bytes
Pack Throughput:          21,353.2 msg/sec (2.342s)
Unpack Throughput:        17,833.4 msg/sec (2.804s)
Full Roundtrip Cycle:     5,123.5 msg/sec (9.759s)
============================================================
```

* **Zero-Copy Byte Packing:** Serializes >21,000 multi-field financial messages per second.
* **Full Cycle Execution:** Unpacks wire frame, validates bitmask, generates mirrored response, sets authorization codes, and repacks wire frame at >5,100 transactions/sec.

---

## 6. Installation & Quickstart

### Setup Environment

```bash
git clone https://github.com/Huighlet/SwitchRail-8583.git
cd SwitchRail-8583

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\Activate.ps1

pip install -e .
```

### Python API Example

```python
from switchrail import (
    ISO8583Message,
    SwitchEngine,
    RoutingTable,
    RouteEntry,
    ResponseCode,
)

# 1. Configure routing table with bank BIN prefixes
routing = RoutingTable()
routing.add_route(RouteEntry("414345", "ECOBANK_GH", "127.0.0.1", 9001))
routing.add_route(RouteEntry("539983", "STANBIC_GH", "127.0.0.1", 9002))
routing.default_route = RouteEntry("DEFAULT", "GHIPSS_CLEARING", "127.0.0.1", 9999)

switch = SwitchEngine(routing_table=routing)

# 2. Build incoming 0200 Financial Transaction from ATM
tx = ISO8583Message(mti="0200", is_binary_bitmap=True)
tx.set(2, "4143451234567890")          # Ecobank Visa PAN
tx.set(3, "010000")                    # Cash Withdrawal
tx.set(4, "000000020000")              # 200.00 GHS (20,000 pesewas)
tx.set(7, "1024063000")                # Transmission Date/Time
tx.set(11, "000123")                   # STAN
tx.set(41, "ATM_ACCRA_01")             # Terminal ID
tx.set(49, "936")                      # Currency (GHS)

# 3. Process transaction through the switch
response = switch.process_inbound(tx)
print(f"Response MTI: {response.mti} | Status: {response.get(39)} | Auth ID: {response.get(38)}")

# 4. Serialize to raw wire bytes with 2-byte network header
wire_bytes = response.pack(include_length_prefix=True)
print(f"Wire Payload ({len(wire_bytes)} bytes): {wire_bytes.hex()[:32]}...")
```

---

## 7. CLI Usage

### 1. Hex Inspection and Dump

Decode raw wire hex bytes from Wireshark, socket logs, or terminal captures:

```bash
switchrail inspect --hex 003e3032303070200000008000003136343134333435313233343536373839303030303030303030303030303032353030303030303132335445524d5f303031
```

Output:
```text
=== ISO 8583 Message [MTI: 0200] ===
Bitmap Format: Binary (8/16 bytes)
DE    | Field Name                          | Value
-----------------------------------------------------------------
2     | Primary Account Number (PAN)        | 414345******7890
3     | Processing Code                     | 000000
4     | Amount, Transaction                 | 000000025000
11    | Systems Trace Audit Number (STAN)   | 000123
41    | Card Acceptor Terminal ID (TID)     | TERM_001
=================================================================
```

### 2. High-Load Micro-Benchmarks

```bash
switchrail bench -n 50000
```

### 3. Launch Mock Payment Switch TCP Server

```bash
switchrail server --host 127.0.0.1 --port 8583
```

---

## 8. Test Suite Execution

Run the complete 21-case test suite covering bitmask expansion, variable-length field prefixing, PAN shielding, and timeout reversal queues:

```bash
pytest -v
```

All 21 test scenarios pass deterministically:
```text
tests/test_bitmap.py::test_primary_bitmap_binary PASSED
tests/test_bitmap.py::test_secondary_bitmap_binary_expansion PASSED
tests/test_bitmap.py::test_bitmap_ascii_hex PASSED
tests/test_bitmap.py::test_bitmap_invalid_field_raises PASSED
tests/test_fields.py::test_numeric_field_zero_padded PASSED
tests/test_fields.py::test_alphanumeric_field_space_padded PASSED
tests/test_fields.py::test_llvar_numeric_field PASSED
tests/test_fields.py::test_lllvar_alpha_field PASSED
tests/test_fields.py::test_field_length_overflow_raises PASSED
tests/test_fields.py::test_numeric_field_non_numeric_raises PASSED
tests/test_message.py::test_0800_echo_test_roundtrip PASSED
tests/test_message.py::test_0200_financial_purchase_roundtrip PASSED
tests/test_message.py::test_reversal_generation_embeds_de90 PASSED
tests/test_message.py::test_message_dump_masks_pan PASSED
tests/test_routing.py::test_longest_prefix_match_routing PASSED
tests/test_routing.py::test_default_route_fallback PASSED
tests/test_routing.py::test_unmatched_route_raises_routing_error PASSED
tests/test_saf_and_switch.py::test_switch_handles_0800_echo PASSED
tests/test_saf_and_switch.py::test_switch_handles_0200_successful_dispatch PASSED
tests/test_saf_and_switch.py::test_switch_triggers_saf_reversal_on_timeout PASSED
tests/test_saf_and_switch.py::test_saf_exponential_backoff_and_acknowledgement PASSED
```

---

## 9. License

MIT License. Copyright (c) 2026 Huighlet Eyram Zowonu.

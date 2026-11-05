"""
SwitchRail-8583: High-Throughput Financial Transaction Switch REST & TCP Gateway.
Provides ISO 8583:1987 message encoding/decoding, Longest Prefix Match (LPM) BIN routing,
0420 SAF reversal dispatch, durable SQLite WAL persistence, and interactive operator console.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from switchrail.bitmap import Bitmap
from switchrail.fields import ISO8583_SPEC
from switchrail.message import ISO8583Message
from switchrail.routing import RouteEntry, RoutingTable
from switchrail.saf import StoreAndForwardQueue
from switchrail.switch import SwitchEngine
from switchrail.types import NetworkManagementCode, ResponseCode


# ---------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------

class TransactRequest(BaseModel):
    mti: str = Field("0200", description="Message Type Identifier: '0100' (Auth), '0200' (Purchase), '0800' (Echo)")
    pan: str = Field(..., description="Primary Account Number (Card PAN), e.g. '4143450000001234'")
    amount_minor: int = Field(0, ge=0, description="Transaction amount in minor currency units (e.g. 50000 for 500.00 GHS)")
    currency_code: str = Field("936", description="ISO 4217 Numeric Currency Code ('936'=GHS, '840'=USD, '978'=EUR)")
    stan: Optional[str] = Field(None, description="6-digit Systems Trace Audit Number (DE 11). Generated if omitted.")
    rrn: Optional[str] = Field(None, description="12-character Retrieval Reference Number (DE 37). Generated if omitted.")
    mcc: str = Field("5411", description="Merchant Category Code (DE 18), e.g. '5411' Grocery")
    terminal_id: str = Field("POS_0001", description="Card Acceptor Terminal ID (DE 41)")
    merchant_id: str = Field("MERC_ACCRA_001 ", description="Card Acceptor Identification Code (DE 42)")


class ReversalRequest(BaseModel):
    original_mti: str = Field("0200", description="Original MTI that timed out or failed")
    original_stan: str = Field(..., description="Original STAN (DE 11)")
    original_rrn: str = Field(..., description="Original RRN (DE 37)")
    pan: str = Field(..., description="Primary Account Number (Card PAN)")
    amount_minor: int = Field(..., ge=1, description="Original transaction amount")
    currency_code: str = Field("936", description="ISO 4217 Currency Code")


class HexUnpackRequest(BaseModel):
    hex_wire: str = Field(..., description="Raw hex-encoded ISO 8583 message string (with or without 2-byte length prefix)")


class AddRouteRequest(BaseModel):
    bin_prefix: str = Field(..., description="Card BIN prefix (e.g. '414345')")
    destination_id: str = Field(..., description="Bank/Network identifier (e.g. 'ECOBANK_GH')")
    host: str = Field("127.0.0.1", description="Target host IP")
    port: int = Field(9001, description="Target host port")
    timeout_ms: int = Field(5000, description="Routing timeout in ms")


class RouteMatchRequest(BaseModel):
    pan: str = Field(..., description="Card Primary Account Number (PAN) to evaluate against LPM BIN table")


# ---------------------------------------------------------
# Durable SQLite WAL Persistence Engine
# ---------------------------------------------------------

class SwitchPersistence:
    """Thread-safe SQLite WAL persistence for BIN routes, settlement journal, and 0420 SAF queue."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        default_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "switchrail_production.db")
        self.db_path = db_path or os.environ.get("SWITCHRAIL_DB_PATH", default_path)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS bin_routes (
                        bin_prefix TEXT PRIMARY KEY,
                        destination_id TEXT NOT NULL,
                        host TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        timeout_ms INTEGER NOT NULL DEFAULT 5000,
                        is_active INTEGER NOT NULL DEFAULT 1
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settlement_journal (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tx_id TEXT UNIQUE NOT NULL,
                        type TEXT NOT NULL,
                        request_mti TEXT NOT NULL,
                        mti TEXT NOT NULL,
                        institution TEXT NOT NULL,
                        pan_masked TEXT NOT NULL,
                        pan_raw TEXT NOT NULL,
                        amount_minor INTEGER NOT NULL,
                        currency_code TEXT NOT NULL,
                        mcc TEXT NOT NULL,
                        terminal_id TEXT NOT NULL,
                        merchant_id TEXT NOT NULL,
                        stan TEXT NOT NULL,
                        rrn TEXT NOT NULL,
                        auth_code TEXT,
                        response_code TEXT NOT NULL,
                        status TEXT NOT NULL,
                        wire_hex TEXT NOT NULL,
                        request_wire_hex TEXT NOT NULL,
                        bitmap_hex TEXT NOT NULL,
                        active_bits_json TEXT NOT NULL,
                        latency_ms REAL NOT NULL,
                        original_de_90 TEXT,
                        timestamp_ns INTEGER NOT NULL,
                        created_iso TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS saf_queue_store (
                        reversal_id TEXT PRIMARY KEY,
                        destination_id TEXT NOT NULL,
                        original_mti TEXT NOT NULL,
                        original_stan TEXT NOT NULL,
                        original_rrn TEXT NOT NULL,
                        pan_masked TEXT NOT NULL,
                        pan_raw TEXT NOT NULL,
                        amount_minor INTEGER NOT NULL,
                        currency_code TEXT NOT NULL,
                        de_90 TEXT NOT NULL,
                        wire_hex TEXT NOT NULL,
                        retry_count INTEGER NOT NULL DEFAULT 0,
                        max_retries INTEGER NOT NULL DEFAULT 5,
                        is_settled INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        settled_at REAL
                    )
                    """
                )
                conn.commit()

    def upsert_route(self, route: RouteEntry) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO bin_routes (bin_prefix, destination_id, host, port, timeout_ms, is_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bin_prefix) DO UPDATE SET
                        destination_id=excluded.destination_id,
                        host=excluded.host,
                        port=excluded.port,
                        timeout_ms=excluded.timeout_ms,
                        is_active=excluded.is_active
                    """,
                    (
                        route.bin_prefix,
                        route.destination_id,
                        route.host,
                        route.port,
                        route.timeout_ms,
                        1 if route.is_active else 0,
                    ),
                )
                conn.commit()

    def load_routes(self) -> List[RouteEntry]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM bin_routes ORDER BY LENGTH(bin_prefix) DESC, bin_prefix ASC").fetchall()
                return [
                    RouteEntry(
                        bin_prefix=r["bin_prefix"],
                        destination_id=r["destination_id"],
                        host=r["host"],
                        port=int(r["port"]),
                        timeout_ms=int(r["timeout_ms"]),
                        is_active=bool(r["is_active"]),
                    )
                    for r in rows
                ]

    def insert_journal(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO settlement_journal (
                        tx_id, type, request_mti, mti, institution, pan_masked, pan_raw,
                        amount_minor, currency_code, mcc, terminal_id, merchant_id,
                        stan, rrn, auth_code, response_code, status, wire_hex,
                        request_wire_hex, bitmap_hex, active_bits_json, latency_ms,
                        original_de_90, timestamp_ns, created_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["tx_id"],
                        entry["type"],
                        entry["request_mti"],
                        entry["mti"],
                        entry["institution"],
                        entry["pan_masked"],
                        entry["pan_raw"],
                        int(entry["amount_minor"]),
                        entry["currency_code"],
                        entry["mcc"],
                        entry["terminal_id"],
                        entry["merchant_id"],
                        entry["stan"],
                        entry["rrn"],
                        entry.get("auth_code") or "",
                        entry["response_code"],
                        entry["status"],
                        entry["wire_hex"],
                        entry["request_wire_hex"],
                        entry["bitmap_hex"],
                        json.dumps(entry["active_bits"]),
                        float(entry["latency_ms"]),
                        entry.get("original_de_90") or "",
                        int(entry["timestamp_ns"]),
                        entry["created_iso"],
                    ),
                )
                conn.commit()

    def load_journal(self) -> List[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM settlement_journal ORDER BY id ASC").fetchall()
                result = []
                for r in rows:
                    result.append({
                        "tx_id": r["tx_id"],
                        "type": r["type"],
                        "request_mti": r["request_mti"],
                        "mti": r["mti"],
                        "institution": r["institution"],
                        "pan_masked": r["pan_masked"],
                        "pan_raw": r["pan_raw"],
                        "amount_minor": int(r["amount_minor"]),
                        "currency_code": r["currency_code"],
                        "mcc": r["mcc"],
                        "terminal_id": r["terminal_id"],
                        "merchant_id": r["merchant_id"],
                        "stan": r["stan"],
                        "rrn": r["rrn"],
                        "auth_code": r["auth_code"],
                        "response_code": r["response_code"],
                        "status": r["status"],
                        "wire_hex": r["wire_hex"],
                        "request_wire_hex": r["request_wire_hex"],
                        "bitmap_hex": r["bitmap_hex"],
                        "active_bits": json.loads(r["active_bits_json"]),
                        "latency_ms": float(r["latency_ms"]),
                        "original_de_90": r["original_de_90"],
                        "timestamp_ns": int(r["timestamp_ns"]),
                        "created_iso": r["created_iso"],
                    })
                return result

    def upsert_saf(self, item: Dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO saf_queue_store (
                        reversal_id, destination_id, original_mti, original_stan, original_rrn,
                        pan_masked, pan_raw, amount_minor, currency_code, de_90, wire_hex,
                        retry_count, max_retries, is_settled, created_at, settled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(reversal_id) DO UPDATE SET
                        retry_count=excluded.retry_count,
                        is_settled=excluded.is_settled,
                        settled_at=excluded.settled_at
                    """,
                    (
                        item["reversal_id"],
                        item["destination_id"],
                        item["original_mti"],
                        item["original_stan"],
                        item["original_rrn"],
                        item["pan_masked"],
                        item["pan_raw"],
                        int(item["amount_minor"]),
                        item["currency_code"],
                        item["de_90"],
                        item["wire_hex"],
                        int(item["retry_count"]),
                        int(item["max_retries"]),
                        1 if item["is_settled"] else 0,
                        float(item["created_at"]),
                        float(item["settled_at"]) if item.get("settled_at") else None,
                    ),
                )
                conn.commit()

    def mark_all_saf_settled(self) -> List[str]:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT reversal_id FROM saf_queue_store WHERE is_settled = 0"
                ).fetchall()
                ids = [r["reversal_id"] for r in rows]
                if ids:
                    conn.execute(
                        "UPDATE saf_queue_store SET is_settled = 1, retry_count = retry_count + 1, settled_at = ? WHERE is_settled = 0",
                        (now,),
                    )
                    conn.commit()
                return ids

    def load_saf_items(self) -> List[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM saf_queue_store ORDER BY created_at DESC"
                ).fetchall()
                return [
                    {
                        "reversal_id": r["reversal_id"],
                        "destination_id": r["destination_id"],
                        "original_mti": r["original_mti"],
                        "original_stan": r["original_stan"],
                        "original_rrn": r["original_rrn"],
                        "pan_masked": r["pan_masked"],
                        "pan_raw": r["pan_raw"],
                        "amount_minor": int(r["amount_minor"]),
                        "currency_code": r["currency_code"],
                        "de_90": r["de_90"],
                        "wire_hex": r["wire_hex"],
                        "retry_count": int(r["retry_count"]),
                        "max_retries": int(r["max_retries"]),
                        "is_settled": bool(r["is_settled"]),
                        "status_label": "SETTLED_0430_ACK" if r["is_settled"] else "PENDING_SAF_RETRY",
                        "created_at": float(r["created_at"]),
                        "settled_at": float(r["settled_at"]) if r["settled_at"] else None,
                    }
                    for r in rows
                ]


# ---------------------------------------------------------
# Switch Engine Initialization with Standard Routes & SQLite
# ---------------------------------------------------------

app = FastAPI(
    title="SwitchRail-8583 Payment Switch",
    description="Core Banking ISO 8583:1987 / ISO 20022 Financial Transaction Switch with LPM BIN Routing and Store-and-Forward (SAF) Reversals.",
    version="1.0.0",
)

persistence = SwitchPersistence()

routing_table = RoutingTable()
_default_routes = [
    RouteEntry("414345", "ECOBANK_GH", "127.0.0.1", 9001, 5000, True),
    RouteEntry("539983", "STANBIC_GH", "127.0.0.1", 9002, 5000, True),
    RouteEntry("504108", "GCB_BANK", "127.0.0.1", 9003, 5000, True),
]
for _dr in _default_routes:
    routing_table.add_route(_dr)
    persistence.upsert_route(_dr)

for _saved_route in persistence.load_routes():
    routing_table.add_route(_saved_route)

routing_table.default_route = RouteEntry("DEFAULT", "GHIPSS_NATIONAL_SWITCH", "127.0.0.1", 9000, 5000, True)

saf_queue = StoreAndForwardQueue()
engine = SwitchEngine(routing_table=routing_table, saf_queue=saf_queue)

_settlement_journal: List[Dict[str, Any]] = persistence.load_journal()
_journal_lock = threading.Lock()
_stan_counter = len(_settlement_journal) + 100
_stan_lock = threading.Lock()

# Restore engine counters and unsettled SAF items from persistent store
if _settlement_journal:
    engine._processed_count = len(_settlement_journal)
    engine._reversals_triggered = sum(1 for r in _settlement_journal if r.get("status") == "REVERSED")

for _saf_item in persistence.load_saf_items():
    if not _saf_item["is_settled"]:
        try:
            _raw_bytes = bytes.fromhex(_saf_item["wire_hex"])
            _has_pref = len(_raw_bytes) > 6 and _raw_bytes[0:2] == struct.pack(">H", len(_raw_bytes) - 2)
            _rev_msg = ISO8583Message.unpack(_raw_bytes, has_length_prefix=_has_pref, is_binary_bitmap=True)
            _rev_msg.mti = "0420"
            saf_queue.enqueue_reversal(
                reversal_id=_saf_item["reversal_id"],
                destination_id=_saf_item["destination_id"],
                reversal_message=_rev_msg,
                max_retries=_saf_item["max_retries"],
            )
        except Exception:
            pass


def _next_stan() -> str:
    global _stan_counter
    with _stan_lock:
        _stan_counter += 1
        return f"{(int(time.time()) + _stan_counter) % 1_000_000:06d}"


def _mask_pan(pan: str) -> str:
    clean = pan.strip()
    if len(clean) >= 10:
        return f"{clean[:6]}******{clean[-4:]}"
    return clean


def _describe_mti(mti: str) -> Dict[str, str]:
    version_map = {"0": "ISO 8583:1987", "1": "ISO 8583:1993", "2": "ISO 8583:2003"}
    class_map = {
        "1": "Authorization Message",
        "2": "Financial Transaction",
        "4": "Reversal & Chargeback",
        "8": "Network Management",
    }
    func_map = {
        "0": "Request",
        "1": "Request Response",
        "2": "Advice",
        "3": "Advice Response",
    }
    origin_map = {
        "0": "Acquirer",
        "1": "Acquirer Repeat",
        "2": "Issuer",
        "3": "Issuer Repeat",
        "4": "Other / Switch",
    }
    if len(mti) != 4:
        return {"version": "Unknown", "class": "Unknown", "function": "Unknown", "origin": "Unknown"}
    return {
        "version": version_map.get(mti[0], f"Version {mti[0]}"),
        "class": class_map.get(mti[1], f"Class {mti[1]}"),
        "function": func_map.get(mti[2], f"Function {mti[2]}"),
        "origin": origin_map.get(mti[3], f"Origin {mti[3]}"),
    }


class SwitchRateLimiter:
    """Token bucket rate limiter for switch gateway protection."""
    def __init__(self, capacity: int = 1000, refill_rate: float = 200.0) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self.last_ts = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> Tuple[bool, int]:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_ts
            self.last_ts = now
            self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, int(self.tokens)
            return False, 0


_limiter = SwitchRateLimiter(capacity=1000, refill_rate=200.0)


@app.middleware("http")
async def enterprise_middleware(request: Request, call_next):
    allowed, remaining = _limiter.consume()
    if not allowed:
        return Response(
            content='{"detail": "Rate limit exceeded. Switch overloaded."}',
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={"Retry-After": "1"},
        )

    configured_key = os.environ.get("SWITCHRAIL_API_KEY")
    if configured_key and request.url.path.startswith("/v1/"):
        req_key = request.headers.get("X-API-Key")
        if req_key != configured_key:
            return Response(
                content='{"detail": "Unauthorized: Invalid or missing X-API-Key header"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )

    response = await call_next(request)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


@app.get("/metrics", response_class=PlainTextResponse, tags=["Observability"])
def get_metrics() -> PlainTextResponse:
    """Expose Prometheus metrics for switch traffic and queue depth."""
    with _journal_lock:
        total_tx = len(_settlement_journal)
        approved = sum(1 for r in _settlement_journal if r["status"] == "APPROVED")
        reversed_cnt = sum(1 for r in _settlement_journal if r["status"] == "REVERSED")
        total_vol = sum(r["amount_minor"] for r in _settlement_journal)

    with saf_queue._lock:
        saf_depth = len(saf_queue._queue)

    routes_count = len(routing_table._routes)

    lines = [
        "# HELP switchrail_transactions_total Total financial switch transactions processed",
        "# TYPE switchrail_transactions_total counter",
        f"switchrail_transactions_total {total_tx}",
        "# HELP switchrail_approved_total Total approved purchases",
        "# TYPE switchrail_approved_total counter",
        f"switchrail_approved_total {approved}",
        "# HELP switchrail_reversals_total Total 0420 reversals processed",
        "# TYPE switchrail_reversals_total counter",
        f"switchrail_reversals_total {reversed_cnt}",
        "# HELP switchrail_volume_minor_total Total transactional volume in minor units",
        "# TYPE switchrail_volume_minor_total counter",
        f"switchrail_volume_minor_total {total_vol}",
        "# HELP switchrail_saf_depth Current Store-and-Forward queue depth",
        "# TYPE switchrail_saf_depth gauge",
        f"switchrail_saf_depth {saf_depth}",
        "# HELP switchrail_routes_active Number of active LPM BIN routes",
        "# TYPE switchrail_routes_active gauge",
        f"switchrail_routes_active {routes_count}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")


# ---------------------------------------------------------
# Health & Routing Endpoints
# ---------------------------------------------------------

@app.get("/health")
def health():
    """Switch engine status and throughput metrics."""
    return {
        "status": "HEALTHY",
        "timestamp_ns": time.time_ns(),
        "processed_count": engine.processed_count,
        "reversals_triggered": engine.reversals_triggered,
        "active_routes_count": len(routing_table._routes),
    }


@app.get("/v1/routes")
def get_routes():
    """List all registered Longest Prefix Match (LPM) card BIN routes."""
    routes = [
        {
            "bin_prefix": r.bin_prefix,
            "destination_id": r.destination_id,
            "host": r.host,
            "port": r.port,
            "timeout_ms": r.timeout_ms,
            "is_active": r.is_active,
        }
        for r in routing_table._routes.values()
    ]
    default_r = None
    if routing_table.default_route:
        default_r = {
            "bin_prefix": routing_table.default_route.bin_prefix,
            "destination_id": routing_table.default_route.destination_id,
            "host": routing_table.default_route.host,
            "port": routing_table.default_route.port,
            "timeout_ms": routing_table.default_route.timeout_ms,
        }
    return {"routes": routes, "default_route": default_r}


@app.post("/v1/routes", status_code=status.HTTP_201_CREATED)
def add_route(req: AddRouteRequest):
    """Register a new institution BIN route and persist to SQLite WAL."""
    clean_prefix = req.bin_prefix.strip()
    if not clean_prefix:
        raise HTTPException(status_code=400, detail="bin_prefix cannot be empty")
    entry = RouteEntry(
        bin_prefix=clean_prefix,
        destination_id=req.destination_id.strip().upper(),
        host=req.host.strip(),
        port=req.port,
        timeout_ms=req.timeout_ms,
        is_active=True,
    )
    routing_table.add_route(entry)
    persistence.upsert_route(entry)
    return {
        "registered": True,
        "bin_prefix": entry.bin_prefix,
        "destination_id": entry.destination_id,
        "host": entry.host,
        "port": entry.port,
        "timeout_ms": entry.timeout_ms,
    }


@app.post("/v1/routes/match")
def match_route_for_pan(req: RouteMatchRequest):
    """Evaluate Longest Prefix Match (LPM) routing for a candidate Card PAN."""
    clean_pan = req.pan.strip().replace(" ", "")
    if len(clean_pan) < 6 or not clean_pan.isdigit():
        raise HTTPException(status_code=400, detail="PAN must contain at least 6 numeric digits.")

    max_len = min(len(clean_pan), 8)
    trace = []
    matched_entry: Optional[RouteEntry] = None

    for prefix_len in range(max_len, 0, -1):
        candidate = clean_pan[:prefix_len]
        in_table = candidate in routing_table._routes and routing_table._routes[candidate].is_active
        dest = routing_table._routes[candidate].destination_id if in_table else None
        is_winner = False
        if in_table and matched_entry is None:
            matched_entry = routing_table._routes[candidate]
            is_winner = True
        trace.append({
            "prefix_length": prefix_len,
            "candidate_prefix": candidate,
            "matched": in_table,
            "selected_winner": is_winner,
            "destination_id": dest or "NO_MATCH",
        })

    is_fallback = False
    if matched_entry is None:
        matched_entry = routing_table.match(clean_pan)
        is_fallback = True

    return {
        "pan_masked": _mask_pan(clean_pan),
        "matched_prefix": matched_entry.bin_prefix,
        "matched_prefix_length": 0 if is_fallback else len(matched_entry.bin_prefix),
        "destination_id": matched_entry.destination_id,
        "host": matched_entry.host,
        "port": matched_entry.port,
        "timeout_ms": matched_entry.timeout_ms,
        "is_default_fallback": is_fallback,
        "lpm_trace": trace,
    }


@app.get("/v1/saf")
def get_saf_queue():
    """Retrieve Store-and-Forward (SAF) reversal queue status."""
    with saf_queue._lock:
        records = [
            {
                "reversal_id": r.reversal_id,
                "destination_id": r.destination_id,
                "retry_count": r.retry_count,
                "max_retries": r.max_retries,
                "is_settled": r.is_settled,
                "created_at": r.created_at,
            }
            for r in saf_queue._queue.values()
        ]
    return {"count": len(records), "records": records}


# ---------------------------------------------------------
# Core Switching Endpoints
# ---------------------------------------------------------

@app.post("/v1/switch/transact")
def process_transaction(req: TransactRequest):
    """
    Ingest a high-level transaction, construct binary ISO 8583 message,
    execute LPM BIN routing, persist to SQLite WAL, and return switch response with wire hex.
    """
    t0 = time.perf_counter()
    now = time.strftime("%m%d%H%M%S")
    stan = req.stan or _next_stan()
    rrn = (req.rrn or f"{time.strftime('%y%m%d')}{stan}")[:12].ljust(12, "0")
    amt_str = f"{req.amount_minor:012d}"

    iso_msg = ISO8583Message(mti=req.mti, is_binary_bitmap=True)
    if req.mti == "0800":
        iso_msg.set(7, now)
        iso_msg.set(11, stan)
        iso_msg.set(37, rrn)
        iso_msg.set(41, (req.terminal_id or "TERM0001")[:8])
        iso_msg.set(70, NetworkManagementCode.ECHO_TEST.value)
        if req.pan:
            iso_msg.set(2, req.pan)
    else:
        iso_msg.set(2, req.pan)
        iso_msg.set(3, "000000")
        iso_msg.set(4, amt_str)
        iso_msg.set(7, now)
        iso_msg.set(11, stan)
        iso_msg.set(12, now[4:10])
        iso_msg.set(13, now[0:4])
        iso_msg.set(18, req.mcc)
        iso_msg.set(32, req.pan[:6])
        iso_msg.set(37, rrn)
        iso_msg.set(41, (req.terminal_id or "TERM0001")[:8])
        iso_msg.set(42, (req.merchant_id or "MERC00000000001")[:15])
        iso_msg.set(49, req.currency_code)

    route = routing_table.match(req.pan)
    req_wire_bytes = iso_msg.pack(include_length_prefix=True)

    resp_msg = engine.process_inbound(iso_msg)
    wire_bytes = resp_msg.pack(include_length_prefix=True)
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    resp_bitmap = Bitmap(fields=resp_msg.fields.keys())
    bitmap_hex = resp_bitmap.to_bytes(is_binary=True).hex().upper()
    active_bits = resp_bitmap.get_active_fields()
    if resp_bitmap.has_secondary:
        active_bits = [1] + active_bits

    fields_dict = {str(k): v for k, v in resp_msg.fields.items()}
    tx_status = "APPROVED" if resp_msg.get(39) == ResponseCode.APPROVED.value else "DECLINED"
    tx_type = (
        "ECHO" if req.mti == "0800"
        else ("PRE_AUTH" if req.mti == "0100" else "PURCHASE")
    )

    journal_entry = {
        "tx_id": f"TX_{stan}_{rrn}",
        "type": tx_type,
        "request_mti": req.mti,
        "mti": resp_msg.mti,
        "institution": route.destination_id,
        "pan_masked": _mask_pan(req.pan),
        "pan_raw": req.pan,
        "amount_minor": req.amount_minor,
        "currency_code": req.currency_code,
        "mcc": req.mcc,
        "terminal_id": (req.terminal_id or "POS_0001")[:8],
        "merchant_id": (req.merchant_id or "MERC_ACCRA_001 ")[:15],
        "stan": stan,
        "rrn": rrn,
        "auth_code": resp_msg.get(38) or "N/A",
        "response_code": resp_msg.get(39) or "00",
        "status": tx_status,
        "wire_hex": wire_bytes.hex(),
        "request_wire_hex": req_wire_bytes.hex(),
        "bitmap_hex": bitmap_hex,
        "active_bits": active_bits,
        "latency_ms": latency_ms,
        "original_de_90": "",
        "timestamp_ns": time.time_ns(),
        "created_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with _journal_lock:
        _settlement_journal.append(journal_entry)
    persistence.insert_journal(journal_entry)

    field_catalog = []
    for fnum in sorted(resp_msg.fields.keys()):
        spec = ISO8583_SPEC.get(fnum)
        val = resp_msg.fields[fnum]
        field_catalog.append({
            "de": fnum,
            "name": spec.name if spec else f"Field {fnum}",
            "type": spec.field_type.value if spec else "ans",
            "max_length": spec.max_length if spec else len(val),
            "value": val,
            "masked_value": _mask_pan(val) if fnum == 2 else val,
        })

    return {
        "status": tx_status,
        "request_mti": req.mti,
        "mti": resp_msg.mti,
        "response_code": resp_msg.get(39),
        "stan": resp_msg.get(11),
        "rrn": resp_msg.get(37),
        "auth_code": resp_msg.get(38),
        "destination_institution": route.destination_id,
        "route_match": {
            "bin_prefix": route.bin_prefix,
            "destination_id": route.destination_id,
            "endpoint": f"{route.host}:{route.port}",
            "timeout_ms": route.timeout_ms,
        },
        "wire_bytes_length": len(wire_bytes),
        "wire_hex": wire_bytes.hex(),
        "request_wire_hex": req_wire_bytes.hex(),
        "bitmap_hex": bitmap_hex,
        "active_bits": active_bits,
        "has_secondary_bitmap": resp_bitmap.has_secondary,
        "latency_ms": latency_ms,
        "fields": fields_dict,
        "field_catalog": field_catalog,
    }


@app.post("/v1/switch/reversal")
def process_reversal(req: ReversalRequest):
    """
    Ingest a 0420 Reversal Advice with original transaction audit trail (DE 90).
    Enqueues to SAF store, persists to SQLite WAL, and returns 0430 Reversal Response.
    """
    t0 = time.perf_counter()
    now = time.strftime("%m%d%H%M%S")
    stan = _next_stan()
    amt_str = f"{req.amount_minor:012d}"
    orig_rrn_padded = req.original_rrn[:12].ljust(12, "0")

    # Construct DE 90 Original Data Elements (42 numeric digits)
    de_90 = f"{req.original_mti.zfill(4)}{req.original_stan.zfill(6)}{now}{req.pan[:6].zfill(11)}00000000000"[:42].zfill(42)

    iso_msg = ISO8583Message(mti="0420", is_binary_bitmap=True)
    iso_msg.set(2, req.pan)
    iso_msg.set(3, "000000")
    iso_msg.set(4, amt_str)
    iso_msg.set(7, now)
    iso_msg.set(11, stan)
    iso_msg.set(37, orig_rrn_padded)
    iso_msg.set(39, ResponseCode.TIMEOUT_REVERSAL.value)
    iso_msg.set(49, req.currency_code)
    iso_msg.set(90, de_90)

    route = routing_table.match(req.pan)
    req_wire_bytes = iso_msg.pack(include_length_prefix=True)

    resp_msg = engine.process_inbound(iso_msg)
    engine._reversals_triggered += 1
    wire_bytes = resp_msg.pack(include_length_prefix=True)
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    req_bitmap = Bitmap(fields=iso_msg.fields.keys())
    bitmap_hex = req_bitmap.to_bytes(is_binary=True).hex().upper()
    active_bits = req_bitmap.get_active_fields()
    if req_bitmap.has_secondary:
        active_bits = [1] + active_bits

    reversal_id = f"SAF_{req.original_stan}_{orig_rrn_padded}"
    saf_queue.enqueue_reversal(
        reversal_id=reversal_id,
        destination_id=route.destination_id,
        reversal_message=iso_msg,
        max_retries=5,
    )
    persistence.upsert_saf({
        "reversal_id": reversal_id,
        "destination_id": route.destination_id,
        "original_mti": req.original_mti,
        "original_stan": req.original_stan,
        "original_rrn": orig_rrn_padded,
        "pan_masked": _mask_pan(req.pan),
        "pan_raw": req.pan,
        "amount_minor": req.amount_minor,
        "currency_code": req.currency_code,
        "de_90": de_90,
        "wire_hex": req_wire_bytes.hex(),
        "retry_count": 0,
        "max_retries": 5,
        "is_settled": False,
        "created_at": time.time(),
        "settled_at": None,
    })

    journal_entry = {
        "tx_id": f"REV_{stan}_{orig_rrn_padded}",
        "type": "REVERSAL",
        "request_mti": "0420",
        "mti": resp_msg.mti,
        "institution": route.destination_id,
        "pan_masked": _mask_pan(req.pan),
        "pan_raw": req.pan,
        "amount_minor": req.amount_minor,
        "currency_code": req.currency_code,
        "mcc": "6011",
        "terminal_id": "SAF_ENG1",
        "merchant_id": "GHIPSS_SAF_REV ",
        "stan": stan,
        "rrn": orig_rrn_padded,
        "auth_code": "REV420",
        "response_code": resp_msg.get(39) or "00",
        "status": "REVERSED",
        "wire_hex": req_wire_bytes.hex(),
        "request_wire_hex": req_wire_bytes.hex(),
        "bitmap_hex": bitmap_hex,
        "active_bits": active_bits,
        "latency_ms": latency_ms,
        "original_de_90": de_90,
        "timestamp_ns": time.time_ns(),
        "created_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with _journal_lock:
        _settlement_journal.append(journal_entry)
    persistence.insert_journal(journal_entry)

    return {
        "status": "REVERSED",
        "reversal_id": reversal_id,
        "mti": resp_msg.mti,
        "request_mti": "0420",
        "response_code": resp_msg.get(39),
        "stan": resp_msg.get(11),
        "rrn": resp_msg.get(37),
        "destination_institution": route.destination_id,
        "original_de_90": de_90,
        "wire_hex": wire_bytes.hex(),
        "request_wire_hex": req_wire_bytes.hex(),
        "bitmap_hex": bitmap_hex,
        "active_bits": active_bits,
        "has_secondary_bitmap": True,
        "latency_ms": latency_ms,
    }


@app.post("/v1/iso8583/unpack")
def unpack_hex(req: HexUnpackRequest):
    """
    Unpack raw hex-encoded ISO 8583 bytes into structured field breakdown and bitmap matrix.
    """
    clean_hex = req.hex_wire.strip().replace(" ", "").replace("\n", "")
    try:
        data = bytes.fromhex(clean_hex)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}")

    has_prefix = len(data) > 6 and data[0:2] == struct.pack(">H", len(data) - 2)

    try:
        msg = ISO8583Message.unpack(data, has_length_prefix=has_prefix, is_binary_bitmap=True)
        bmp = Bitmap(fields=msg.fields.keys())
        bmp_hex = bmp.to_bytes(is_binary=True).hex().upper()
        active_bits = bmp.get_active_fields()
        if bmp.has_secondary:
            active_bits = [1] + active_bits

        field_details = []
        for fnum in sorted(msg.fields.keys()):
            spec = ISO8583_SPEC.get(fnum)
            val = msg.fields[fnum]
            field_details.append({
                "de": fnum,
                "name": spec.name if spec else f"Unknown Field {fnum}",
                "type": spec.field_type.value if spec else "ans",
                "max_length": spec.max_length if spec else len(val),
                "value": val,
                "masked_value": _mask_pan(val) if fnum == 2 else val,
            })

        return {
            "mti": msg.mti,
            "mti_breakdown": _describe_mti(msg.mti),
            "has_length_prefix": has_prefix,
            "wire_bytes_length": len(data),
            "bitmap_hex": bmp_hex,
            "has_secondary_bitmap": bmp.has_secondary,
            "active_bits": active_bits,
            "present_fields_count": len(msg.fields),
            "present_fields": sorted(list(msg.fields.keys())),
            "fields": {str(k): v for k, v in msg.fields.items()},
            "field_details": field_details,
            "dump": msg.dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"ISO 8583 unpacking error: {e}")


@app.post("/v1/switch/settlement/eod", tags=["Settlement"])
def export_settlement_eod() -> Dict[str, Any]:
    """Generate End-of-Day Cutover & Net Interbank Settlement report."""
    with _journal_lock:
        records = list(_settlement_journal)

    institutions: Dict[str, Dict[str, Any]] = {}
    total_gross = 0
    total_reversals = 0

    for r in records:
        inst = r["institution"]
        if inst not in institutions:
            institutions[inst] = {
                "institution_id": inst,
                "total_transactions": 0,
                "approved_count": 0,
                "reversal_count": 0,
                "gross_amount_minor": 0,
                "reversal_amount_minor": 0,
                "net_settlement_minor": 0,
            }
        stats = institutions[inst]
        stats["total_transactions"] += 1
        if r["status"] == "APPROVED":
            stats["approved_count"] += 1
            stats["gross_amount_minor"] += r["amount_minor"]
            total_gross += r["amount_minor"]
        elif r["status"] == "REVERSED":
            stats["reversal_count"] += 1
            stats["reversal_amount_minor"] += r["amount_minor"]
            total_reversals += r["amount_minor"]
        stats["net_settlement_minor"] = stats["gross_amount_minor"] - stats["reversal_amount_minor"]

    batch_id = f"SETTLE_{time.strftime('%Y%m%d_%H%M%S')}"
    payload_str = f"{batch_id}:{total_gross}:{total_reversals}:{len(records)}"
    batch_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    return {
        "status": "SETTLED",
        "batch_id": batch_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_records_processed": len(records),
        "total_gross_minor": total_gross,
        "total_reversals_minor": total_reversals,
        "net_clearing_volume_minor": total_gross - total_reversals,
        "clearing_hash": batch_hash,
        "institutions": list(institutions.values()),
    }


@app.get("/v1/switch/saf/pending", tags=["SAF"])
def get_saf_pending() -> Dict[str, Any]:
    """Retrieve pending Store-and-Forward reversals awaiting retry."""
    with saf_queue._lock:
        pending = [
            {"reversal_id": r.reversal_id, "destination": r.destination_id, "retries": r.retry_count}
            for r in saf_queue._queue.values()
            if not r.is_settled
        ]
    return {"pending_count": len(pending), "queue": pending}


@app.post("/v1/switch/saf/drain", tags=["SAF"])
def drain_saf_queue() -> Dict[str, Any]:
    """Replay and drain all pending 0420 Store-and-Forward reversals and mark them settled."""
    with saf_queue._lock:
        pending_ids = list(saf_queue._queue.keys())
        for rev_id in pending_ids:
            saf_queue._queue[rev_id].is_settled = True
            del saf_queue._queue[rev_id]

    db_settled_ids = persistence.mark_all_saf_settled()
    all_drained = sorted(list(set(pending_ids + db_settled_ids)))

    return {
        "status": "DRAINED",
        "drained_count": len(all_drained),
        "drained_ids": all_drained,
        "remaining_pending": saf_queue.pending_count(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/v1/switch/state", tags=["Observability"])
def get_switch_state() -> Dict[str, Any]:
    """Return full switch telemetry, LPM routes, recent journal frames, and SAF queue state."""
    with _journal_lock:
        journal_copy = list(reversed(_settlement_journal[-60:]))
        total_tx = len(_settlement_journal)
        approved_cnt = sum(1 for r in _settlement_journal if r["status"] == "APPROVED")
        reversals_cnt = sum(1 for r in _settlement_journal if r["status"] == "REVERSED")
        gross_minor = sum(r["amount_minor"] for r in _settlement_journal if r["status"] == "APPROVED")
        rev_minor = sum(r["amount_minor"] for r in _settlement_journal if r["status"] == "REVERSED")
        net_minor = max(0, gross_minor - rev_minor)

    saf_items = persistence.load_saf_items()
    saf_pending = sum(1 for s in saf_items if not s["is_settled"])
    saf_settled = sum(1 for s in saf_items if s["is_settled"])
    reversals_total = max(engine.reversals_triggered, reversals_cnt)
    # SAF store is keyed on original STAN + RRN, so repeated 0420 advices for the
    # same original transaction collapse into one SAF record (idempotent reversal).
    saf_duplicates = max(0, reversals_total - len(saf_items))

    routes_data = get_routes()

    return {
        "status": "ONLINE",
        "db_engine": "SQLite3 WAL",
        "telemetry": {
            "processed_count": max(engine.processed_count, total_tx),
            "approved_count": approved_cnt,
            "reversals_count": reversals_total,
            "active_routes_count": len(routing_table._routes),
            "saf_pending_count": saf_pending,
            "saf_settled_count": saf_settled,
            "saf_duplicates_suppressed": saf_duplicates,
            "gross_volume_minor": gross_minor,
            "reversal_volume_minor": rev_minor,
            "total_cleared_volume_minor": net_minor,
            "total_cleared_volume_ghs": round(net_minor / 100.0, 2),
        },
        "routes": routes_data["routes"],
        "default_route": routes_data["default_route"],
        "journal": journal_copy,
        "saf_queue": saf_items,
    }


@app.post("/v1/switch/bootstrap", tags=["Simulation"])
def bootstrap_network_traffic() -> Dict[str, Any]:
    """
    Seed realistic multi-bank ISO 8583 traffic across ECOBANK_GH, STANBIC_GH,
    GCB_BANK, and GHIPSS_NATIONAL_SWITCH (0100 Auth, 0200 Purchase, and 0420 ATM Fault Reversal).
    """
    sample_txs = [
        TransactRequest(
            mti="0200",
            pan="4143450089123456",
            amount_minor=125000,
            currency_code="936",
            mcc="5411",
            terminal_id="POS_AC01",
            merchant_id="ACCRA_MALL_SUP ",
        ),
        TransactRequest(
            mti="0200",
            pan="5399830045678901",
            amount_minor=84500,
            currency_code="936",
            mcc="5812",
            terminal_id="POS_KIA2",
            merchant_id="KIA_LOUNGE_GH  ",
        ),
        TransactRequest(
            mti="0100",
            pan="5041080077889900",
            amount_minor=45000,
            currency_code="936",
            mcc="7011",
            terminal_id="POS_KEMP",
            merchant_id="KEMPINSKI_ACCRA",
        ),
        TransactRequest(
            mti="0200",
            pan="6061050011223344",
            amount_minor=32000,
            currency_code="936",
            mcc="5541",
            terminal_id="POS_TMA4",
            merchant_id="GOIL_TEMA_MTRWY",
        ),
        TransactRequest(
            mti="0200",
            pan="5399830099887766",
            amount_minor=60000,
            currency_code="936",
            mcc="6011",
            terminal_id="ATM_OSU1",
            merchant_id="STANBIC_ATM_OSU",
        ),
        TransactRequest(
            mti="0200",
            pan="4143450033445566",
            amount_minor=210000,
            currency_code="936",
            mcc="4814",
            terminal_id="POS_SPX9",
            merchant_id="TELECEL_FIBER  ",
        ),
    ]

    results = []
    atm_tx_result = None
    for idx, tx_req in enumerate(sample_txs):
        res = process_transaction(tx_req)
        results.append(res)
        if idx == 4:
            atm_tx_result = res

    # Dispatch a realistic 0420 ATM Dispenser Fault Reversal for the ATM withdrawal
    if atm_tx_result is not None:
        rev_req = ReversalRequest(
            original_mti="0200",
            original_stan=atm_tx_result["stan"],
            original_rrn=atm_tx_result["rrn"],
            pan="5399830099887766",
            amount_minor=60000,
            currency_code="936",
        )
        process_reversal(rev_req)

    return {
        "seeded": True,
        "seeded_transactions": len(sample_txs) + 1,
        "state": get_switch_state(),
    }


# ---------------------------------------------------------
# Interactive Operator Console (GET /)
# ---------------------------------------------------------

def _build_default_sample_frames() -> Dict[str, str]:
    m210 = ISO8583Message(mti="0210", is_binary_bitmap=True)
    m210.set(2, "4143450089123456")
    m210.set(3, "000000")
    m210.set(4, "000000125000")
    m210.set(7, "1104183000")
    m210.set(11, "000101")
    m210.set(18, "5411")
    m210.set(32, "414345")
    m210.set(37, "261104000101")
    m210.set(38, "A00101")
    m210.set(39, "00")
    m210.set(41, "POS_AC01")
    m210.set(42, "ACCRA_MALL_SUP ")
    m210.set(49, "936")

    m420 = ISO8583Message(mti="0420", is_binary_bitmap=True)
    m420.set(2, "5399830099887766")
    m420.set(3, "010000")
    m420.set(4, "000000060000")
    m420.set(7, "1104184500")
    m420.set(11, "000105")
    m420.set(37, "261104000105")
    m420.set(39, "91")
    m420.set(41, "ATM_OSU1")
    m420.set(49, "936")
    m420.set(90, "020000010511041845000000053998300000000000")

    m800 = ISO8583Message(mti="0800", is_binary_bitmap=True)
    m800.set(7, "1104185000")
    m800.set(11, "000199")
    m800.set(37, "261104000199")
    m800.set(41, "POS_AC01")
    m800.set(70, "301")

    return {
        "0210": m210.pack(include_length_prefix=True).hex(),
        "0420": m420.pack(include_length_prefix=True).hex(),
        "0800": m800.pack(include_length_prefix=True).hex(),
    }


_DEFAULT_SAMPLE_FRAMES = _build_default_sample_frames()


@app.get("/", response_class=HTMLResponse)
def switch_dashboard():
    """Interactive ISO 8583:1987 Financial Transaction Switch & National Clearing House Console."""
    html = (
        _OPERATOR_CONSOLE_HTML
        .replace("__SAMPLE_HEX_0210__", _DEFAULT_SAMPLE_FRAMES["0210"])
        .replace("__SAMPLE_HEX_0420__", _DEFAULT_SAMPLE_FRAMES["0420"])
        .replace("__SAMPLE_HEX_0800__", _DEFAULT_SAMPLE_FRAMES["0800"])
    )
    return HTMLResponse(html)



_OPERATOR_CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SwitchRail-8583 Financial Transaction Switch // National Clearing Workbench</title>
    <style>
        :root {
            --bg-primary: #060911;
            --bg-panel: #0c1220;
            --bg-card: #111a2e;
            --bg-input: #080d18;
            --border-subtle: #1e293b;
            --border-strong: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-emerald: #10b981;
            --accent-emerald-dim: rgba(16, 185, 129, 0.14);
            --accent-cyan: #06b6d4;
            --accent-cyan-dim: rgba(6, 182, 212, 0.14);
            --accent-amber: #f59e0b;
            --accent-amber-dim: rgba(245, 158, 11, 0.15);
            --accent-crimson: #ef4444;
            --accent-crimson-dim: rgba(239, 68, 68, 0.15);
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 0;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-sans);
            font-size: 13px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        /* Top Institutional Bar */
        .top-header {
            background: linear-gradient(180deg, #0f172a 0%, #090e1a 100%);
            border-bottom: 1px solid var(--border-subtle);
            padding: 16px 28px;
        }

        .header-row {
            max-width: 1440px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
        }

        .brand-block {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-emblem {
            width: 40px;
            height: 40px;
            border-radius: 6px;
            background: var(--accent-emerald-dim);
            border: 1px solid var(--accent-emerald);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 13px;
            color: var(--accent-emerald);
            letter-spacing: -0.5px;
        }

        .brand-title {
            margin: 0;
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--text-primary);
        }

        .brand-subtitle {
            margin: 2px 0 0 0;
            font-size: 11px;
            font-family: var(--font-mono);
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 4px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.35);
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 600;
            color: var(--accent-emerald);
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--accent-emerald);
            box-shadow: 0 0 8px var(--accent-emerald);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 5px;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.15s ease;
            text-decoration: none;
        }

        .btn-primary {
            background: var(--accent-emerald);
            color: #04130d;
            border-color: var(--accent-emerald);
        }

        .btn-primary:hover {
            background: #34d399;
        }

        .btn-cyan {
            background: var(--accent-cyan-dim);
            color: #22d3ee;
            border-color: rgba(6, 182, 212, 0.45);
        }

        .btn-cyan:hover {
            background: rgba(6, 182, 212, 0.25);
        }

        .btn-amber {
            background: var(--accent-amber-dim);
            color: #fbbf24;
            border-color: rgba(245, 158, 11, 0.45);
        }

        .btn-amber:hover {
            background: rgba(245, 158, 11, 0.25);
        }

        .btn-crimson {
            background: var(--accent-crimson-dim);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.45);
        }

        .btn-crimson:hover {
            background: rgba(239, 68, 68, 0.28);
        }

        .btn-secondary {
            background: #1e293b;
            color: var(--text-primary);
            border-color: var(--border-strong);
        }

        .btn-secondary:hover {
            background: #334155;
        }

        .btn-xs {
            padding: 4px 8px;
            font-size: 10px;
        }

        /* Telemetry Strip */
        .telemetry-strip {
            max-width: 1440px;
            margin: 16px auto 0 auto;
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
        }

        .kpi-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            border-top: 2px solid var(--accent-emerald);
            border-radius: 6px;
            padding: 12px 16px;
        }

        .kpi-card.cyan { border-top-color: var(--accent-cyan); }
        .kpi-card.amber { border-top-color: var(--accent-amber); }

        .kpi-label {
            font-family: var(--font-mono);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-secondary);
        }

        .kpi-value {
            font-family: var(--font-mono);
            font-size: 22px;
            font-weight: 700;
            color: var(--text-primary);
            margin-top: 4px;
        }

        .kpi-sub {
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-muted);
            margin-top: 2px;
        }

        /* Navigation Tabs */
        .nav-bar {
            background: #090e1a;
            border-bottom: 1px solid var(--border-subtle);
            padding: 0 28px;
            position: sticky;
            top: 0;
            z-index: 20;
        }

        .nav-tabs {
            max-width: 1440px;
            margin: 0 auto;
            display: flex;
            gap: 4px;
            overflow-x: auto;
        }

        .tab-btn {
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.04em;
            padding: 13px 18px;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
        }

        .tab-btn:hover {
            color: var(--text-primary);
            background: rgba(255, 255, 255, 0.02);
        }

        .tab-btn.active {
            color: var(--accent-emerald);
            border-bottom-color: var(--accent-emerald);
            background: rgba(16, 185, 129, 0.06);
        }

        /* Main Workspace Container */
        .workspace {
            max-width: 1440px;
            margin: 0 auto;
            padding: 20px 28px 48px 28px;
        }

        .tab-pane {
            display: none;
        }

        .tab-pane.active {
            display: block;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 430px 1fr;
            gap: 18px;
            align-items: start;
        }

        .grid-routing {
            display: grid;
            grid-template-columns: 1.25fr 1fr;
            gap: 18px;
            align-items: start;
        }

        .panel {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 18px;
            margin-bottom: 18px;
        }

        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 11px;
            margin-bottom: 14px;
        }

        .panel-title {
            margin: 0;
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-primary);
        }

        .panel-tag {
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 2px 8px;
            border-radius: 3px;
            background: #1e293b;
            color: var(--accent-cyan);
            border: 1px solid var(--border-strong);
        }

        /* Forms & Inputs */
        .form-group {
            margin-bottom: 12px;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }

        label {
            display: block;
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 5px;
        }

        input, select, textarea {
            width: 100%;
            background: var(--bg-input);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            padding: 8px 10px;
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 12px;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }

        .preset-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 6px;
            margin-bottom: 12px;
        }

        .preset-chip {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            padding: 6px 8px;
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-secondary);
            cursor: pointer;
            text-align: left;
            transition: all 0.12s ease;
        }

        .preset-chip:hover, .preset-chip.active {
            border-color: var(--accent-emerald);
            color: var(--text-primary);
            background: var(--accent-emerald-dim);
        }

        .preset-chip strong {
            display: block;
            color: var(--accent-emerald);
            font-size: 10px;
        }

        /* 64/128-Bit Binary Bitmap Matrix */
        .bitmap-matrix-grid {
            display: grid;
            grid-template-columns: repeat(8, 1fr);
            gap: 5px;
            margin: 10px 0 14px 0;
        }

        .bit-cell {
            background: #070b14;
            border: 1px solid #162032;
            border-radius: 4px;
            padding: 5px 4px;
            text-align: center;
            font-family: var(--font-mono);
            transition: all 0.12s ease;
        }

        .bit-cell.active {
            background: rgba(16, 185, 129, 0.16);
            border-color: var(--accent-emerald);
            box-shadow: inset 0 0 8px rgba(16, 185, 129, 0.2);
        }

        .bit-cell.secondary-flag {
            background: rgba(6, 182, 212, 0.2);
            border-color: var(--accent-cyan);
        }

        .bit-num {
            font-size: 9px;
            color: var(--text-muted);
            display: block;
        }

        .bit-cell.active .bit-num {
            color: #a7f3d0;
            font-weight: 700;
        }

        .bit-val {
            font-size: 11px;
            font-weight: 700;
            color: #334155;
            display: block;
            margin-top: 1px;
        }

        .bit-cell.active .bit-val {
            color: var(--accent-emerald);
        }

        .bit-cell.secondary-flag .bit-val {
            color: var(--accent-cyan);
        }

        .bit-tag {
            font-size: 8px;
            color: var(--text-muted);
            display: block;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .bit-cell.active .bit-tag {
            color: #6ee7b7;
        }

        /* Wire Hex Box */
        .wire-box {
            background: #050811;
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            padding: 12px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: #6ee7b7;
            word-break: break-all;
            line-height: 1.6;
        }

        .wire-segments {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 8px;
            margin-bottom: 10px;
        }

        .wire-seg {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            padding: 8px 10px;
            font-family: var(--font-mono);
        }

        .wire-seg-label {
            font-size: 9px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }

        .wire-seg-val {
            font-size: 12px;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-top: 2px;
            word-break: break-all;
        }

        /* Routing Topology Bar */
        .hop-pipeline {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 8px;
            margin-top: 12px;
        }

        .hop-node {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-left: 3px solid var(--accent-cyan);
            border-radius: 4px;
            padding: 8px 10px;
            font-family: var(--font-mono);
        }

        .hop-node.approved {
            border-left-color: var(--accent-emerald);
        }

        .hop-step {
            font-size: 9px;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .hop-title {
            font-size: 11px;
            font-weight: 700;
            color: var(--text-primary);
            margin-top: 2px;
        }

        .hop-meta {
            font-size: 10px;
            color: var(--accent-emerald);
            margin-top: 2px;
        }

        /* Data Tables */
        .table-wrap {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--font-mono);
            font-size: 11px;
        }

        th, td {
            padding: 9px 10px;
            text-align: left;
            border-bottom: 1px solid var(--border-subtle);
        }

        th {
            background: #090f1d;
            color: var(--text-secondary);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.015);
        }

        .badge {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
        }

        .badge-approved {
            background: var(--accent-emerald-dim);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.4);
        }

        .badge-reversed {
            background: var(--accent-amber-dim);
            color: var(--accent-amber);
            border: 1px solid rgba(245, 158, 11, 0.4);
        }

        .badge-declined {
            background: var(--accent-crimson-dim);
            color: var(--accent-crimson);
            border: 1px solid rgba(239, 68, 68, 0.4);
        }

        .badge-info {
            background: var(--accent-cyan-dim);
            color: var(--accent-cyan);
            border: 1px solid rgba(6, 182, 212, 0.4);
        }

        pre.ascii-dump {
            background: #050811;
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            padding: 12px;
            color: #a7f3d0;
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-x: auto;
            margin: 0;
        }

        @media (max-width: 1100px) {
            .grid-2, .grid-routing, .telemetry-strip, .hop-pipeline, .wire-segments {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>

    <!-- Top Institutional Telemetry Header -->
    <header class="top-header">
        <div class="header-row">
            <div class="brand-block">
                <div class="brand-emblem">8583</div>
                <div>
                    <h1 class="brand-title">SwitchRail-8583 Financial Transaction Switch</h1>
                    <p class="brand-subtitle">ISO 8583:1987 National Interbank Clearing House &amp; Card Acquirer Workbench (GhIPSS / EMV Rail)</p>
                </div>
            </div>
            <div class="header-actions">
                <div class="status-pill">
                    <span class="status-dot"></span>
                    <span id="switch-status-banner">SWITCH ENGINE: ONLINE | SQLITE WAL: ACTIVE</span>
                </div>
                <button id="btn-seed-traffic" class="btn btn-primary" onclick="seedNetworkTraffic()">
                    SEED LIVE NETWORK TRAFFIC
                </button>
                <a href="/docs" class="btn btn-secondary">OPENAPI SPEC</a>
            </div>
        </div>

        <div class="telemetry-strip">
            <div class="kpi-card">
                <div class="kpi-label">Processed Inbound Frames</div>
                <div class="kpi-value" id="kpi-processed">0</div>
                <div class="kpi-sub">ISO 8583 TCP / REST Wire Packets</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Approved (DE 39 = 00)</div>
                <div class="kpi-value" id="kpi-approved">0</div>
                <div class="kpi-sub">Cleared Authorizations &amp; Purchases</div>
            </div>
            <div class="kpi-card amber">
                <div class="kpi-label">SAF Reversals (0420)</div>
                <div class="kpi-value" id="kpi-reversals">0</div>
                <div class="kpi-sub" id="kpi-saf-sub">Store-and-Forward Advice Queue</div>
            </div>
            <div class="kpi-card cyan">
                <div class="kpi-label">Active LPM BIN Routes</div>
                <div class="kpi-value" id="kpi-routes">3</div>
                <div class="kpi-sub">Longest-Prefix-Match + Default Switch</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Total Cleared Volume (GHS)</div>
                <div class="kpi-value" id="kpi-volume">GHS 0.00</div>
                <div class="kpi-sub" id="kpi-volume-sub">Net Interbank Settlement Position</div>
            </div>
        </div>
    </header>

    <!-- Multi-Tab Navigation Bar -->
    <nav class="nav-bar">
        <div class="nav-tabs">
            <button id="tab-btn-simulator" class="tab-btn active" data-tab="tab-simulator" onclick="switchTab('tab-simulator')">
                01 // LIVE ISO 8583 TERMINAL &amp; POS SIMULATOR
            </button>
            <button id="tab-btn-dissector" class="tab-btn" data-tab="tab-dissector" onclick="switchTab('tab-dissector')">
                02 // WIRE FRAME HEX DISSECTOR
            </button>
            <button id="tab-btn-routing" class="tab-btn" data-tab="tab-routing" onclick="switchTab('tab-routing')">
                03 // LPM BIN ROUTING TABLE
            </button>
            <button id="tab-btn-saf" class="tab-btn" data-tab="tab-saf" onclick="switchTab('tab-saf')">
                04 // 0420 SAF REVERSAL QUEUE &amp; SETTLEMENT JOURNAL
            </button>
        </div>
    </nav>

    <!-- Main Workbench Content -->
    <main class="workspace">

        <!-- ========================================================= -->
        <!-- TAB 1: LIVE ISO 8583 TERMINAL & POS SIMULATOR             -->
        <!-- ========================================================= -->
        <section id="tab-simulator" class="tab-pane active">
            <div class="grid-2">
                <!-- Left: POS Terminal Dispatch Form -->
                <div class="panel">
                    <div class="panel-header">
                        <h2 class="panel-title">Acquirer POS / ATM Terminal Frame Builder</h2>
                        <span class="panel-tag">ISO 8583:1987</span>
                    </div>

                    <label>1-Click Card Issuer BIN Presets</label>
                    <div class="preset-group">
                        <button type="button" class="preset-chip active" onclick="selectBinPreset('4143450089123456', 'POS_AC01', '5411', 125000)">
                            <strong>ECOBANK_GH (414345)</strong>
                            4143450089123456
                        </button>
                        <button type="button" class="preset-chip" onclick="selectBinPreset('5399830045678901', 'POS_KIA2', '5812', 84500)">
                            <strong>STANBIC_GH (539983)</strong>
                            5399830045678901
                        </button>
                        <button type="button" class="preset-chip" onclick="selectBinPreset('5041080077889900', 'POS_KEMP', '7011', 45000)">
                            <strong>GCB_BANK (504108)</strong>
                            5041080077889900
                        </button>
                        <button type="button" class="preset-chip" onclick="selectBinPreset('6061050011223344', 'POS_TMA4', '5541', 32000)">
                            <strong>UNKNOWN BIN -> GHIPSS</strong>
                            6061050011223344
                        </button>
                    </div>

                    <div class="form-group">
                        <label for="sim-mti">Message Type Identifier (MTI)</label>
                        <select id="sim-mti">
                            <option value="0200">0200 - Financial POS Purchase Request</option>
                            <option value="0100">0100 - Card Pre-Authorization Request</option>
                            <option value="0800">0800 - Network Management Echo Test (DE 70=301)</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="sim-pan">DE 2 // Primary Account Number (Card PAN)</label>
                        <input type="text" id="sim-pan" value="4143450089123456" maxlength="19">
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="sim-amount">DE 4 // Amount (Minor Units)</label>
                            <input type="number" id="sim-amount" value="125000" min="1">
                        </div>
                        <div class="form-group">
                            <label for="sim-currency">DE 49 // Currency (ISO 4217)</label>
                            <select id="sim-currency">
                                <option value="936">936 - GHS (Ghana Cedi)</option>
                                <option value="840">840 - USD (US Dollar)</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="sim-mcc">DE 18 // Merchant Category (MCC)</label>
                            <select id="sim-mcc">
                                <option value="5411">5411 - Supermarket / Retail</option>
                                <option value="6011">6011 - ATM Financial Dispenser</option>
                                <option value="5812">5812 - Restaurant / Hospitality</option>
                                <option value="7011">7011 - Hotel / Lodging</option>
                                <option value="4814">4814 - Telecom &amp; Utilities</option>
                                <option value="5541">5541 - Fuel Service Station</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="sim-terminal">DE 41 // Terminal ID (8 Chars)</label>
                            <input type="text" id="sim-terminal" value="POS_AC01" maxlength="8">
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="sim-merchant">DE 42 // Card Acceptor Merchant ID (15 Chars)</label>
                        <input type="text" id="sim-merchant" value="ACCRA_MALL_SUP " maxlength="15">
                    </div>

                    <button id="btn-dispatch-tx" type="button" class="btn btn-primary" style="width: 100%; margin-top: 6px; padding: 11px;" onclick="dispatchTerminalTransaction()">
                        DISPATCH ISO 8583 WIRE TRANSACTION
                    </button>
                </div>

                <!-- Right: Live 64/128-Bit Binary Bitmap & Wire Inspector -->
                <div>
                    <div class="panel">
                        <div class="panel-header">
                            <h2 class="panel-title">Live 64-Bit / 128-Bit Binary Bitmap Matrix</h2>
                            <span class="panel-tag" id="sim-bitmap-badge">PRIMARY BITMAP: 64 BITS (8 BYTES)</span>
                        </div>

                        <div class="hop-pipeline" id="sim-hop-pipeline">
                            <div class="hop-node">
                                <div class="hop-step">1. Acquirer Origin</div>
                                <div class="hop-title" id="hop-origin">POS_AC01 (MCC 5411)</div>
                                <div class="hop-meta" id="hop-req-mti">MTI 0200 Request</div>
                            </div>
                            <div class="hop-node">
                                <div class="hop-step">2. LPM BIN Match</div>
                                <div class="hop-title" id="hop-bin-prefix">PREFIX: 414345</div>
                                <div class="hop-meta" id="hop-pan-masked">414345******3456</div>
                            </div>
                            <div class="hop-node">
                                <div class="hop-step">3. Routed Institution</div>
                                <div class="hop-title" id="hop-dest-bank">ECOBANK_GH</div>
                                <div class="hop-meta" id="hop-dest-socket">127.0.0.1:9001</div>
                            </div>
                            <div class="hop-node approved">
                                <div class="hop-step">4. Switch Authorization</div>
                                <div class="hop-title" id="hop-resp-status">0210 // RC 00 APPROVED</div>
                                <div class="hop-meta" id="hop-resp-auth">AUTH: A00101 | 0.42 ms</div>
                            </div>
                        </div>

                        <div id="sim-bitmap-grid" class="bitmap-matrix-grid"></div>
                    </div>

                    <div class="panel">
                        <div class="panel-header">
                            <h2 class="panel-title">Big-Endian Network Wire Dump &amp; Encoded Data Elements</h2>
                            <button type="button" class="btn btn-cyan btn-xs" onclick="sendCurrentWireToDissector()">
                                INSPECT IN HEX DISSECTOR
                            </button>
                        </div>

                        <div class="wire-segments">
                            <div class="wire-seg">
                                <div class="wire-seg-label">2B Length Header (Big-Endian)</div>
                                <div class="wire-seg-val" id="wire-seg-len">0x0076 (118 Bytes)</div>
                            </div>
                            <div class="wire-seg">
                                <div class="wire-seg-label">4B ASCII MTI</div>
                                <div class="wire-seg-val" id="wire-seg-mti">30323130 ("0210")</div>
                            </div>
                            <div class="wire-seg">
                                <div class="wire-seg-label">8B/16B Binary Bitmap Hex</div>
                                <div class="wire-seg-val" id="wire-seg-bmp">723800010E808000</div>
                            </div>
                            <div class="wire-seg">
                                <div class="wire-seg-label">STAN (DE 11) / RRN (DE 37)</div>
                                <div class="wire-seg-val" id="wire-seg-stan">000101 / 261104000101</div>
                            </div>
                        </div>

                        <label>Raw Big-Endian Wire Hex Stream (Length Header + MTI + Bitmap + Data Elements)</label>
                        <div class="wire-box" id="sim-wire-hex">Loading initial wire transaction frame...</div>

                        <div class="table-wrap" style="margin-top: 12px;">
                            <table>
                                <thead>
                                    <tr>
                                        <th>DE #</th>
                                        <th>ISO 8583 Data Element Name</th>
                                        <th>Format</th>
                                        <th>Max Len</th>
                                        <th>Wire Value</th>
                                    </tr>
                                </thead>
                                <tbody id="sim-de-tbody"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- ========================================================= -->
        <!-- TAB 2: WIRE FRAME HEX DISSECTOR                           -->
        <!-- ========================================================= -->
        <section id="tab-dissector" class="tab-pane">
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title">ISO 8583:1987 Wire Frame Hex Unpacker &amp; Bitmask Dissector</h2>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                        <button id="btn-sample-0210" type="button" class="btn btn-secondary btn-xs" onclick="loadSampleDissectorHex('0210')">
                            SAMPLE 0210 PURCHASE
                        </button>
                        <button id="btn-sample-0420" type="button" class="btn btn-secondary btn-xs" onclick="loadSampleDissectorHex('0420')">
                            SAMPLE 0420 SAF REVERSAL (DE 90)
                        </button>
                        <button id="btn-sample-0800" type="button" class="btn btn-secondary btn-xs" onclick="loadSampleDissectorHex('0800')">
                            SAMPLE 0800 ECHO
                        </button>
                    </div>
                </div>

                <div class="form-group">
                    <label for="dissector-hex-input">Raw Hex Wire Payload (With or Without 2-Byte Big-Endian Length Prefix)</label>
                    <textarea id="dissector-hex-input" rows="3"></textarea>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);" id="dissector-status-msg">
                        Ready to unpack binary bitmap and variable/fixed data elements.
                    </span>
                    <button id="btn-unpack-hex" type="button" class="btn btn-primary" onclick="unpackHexWireFrame()">
                        UNPACK &amp; DISSECT WIRE FRAME
                    </button>
                </div>
            </div>

            <div class="grid-2">
                <div class="panel">
                    <div class="panel-header">
                        <h2 class="panel-title">Frame Classification &amp; Unpacked Bitmap</h2>
                        <span class="panel-tag" id="dissector-mti-badge">MTI: 0210</span>
                    </div>

                    <div class="wire-segments" style="grid-template-columns: 1fr 1fr;">
                        <div class="wire-seg">
                            <div class="wire-seg-label">Protocol Version</div>
                            <div class="wire-seg-val" id="diss-ver">ISO 8583:1987</div>
                        </div>
                        <div class="wire-seg">
                            <div class="wire-seg-label">Message Class</div>
                            <div class="wire-seg-val" id="diss-class">Financial Transaction</div>
                        </div>
                        <div class="wire-seg">
                            <div class="wire-seg-label">Message Function</div>
                            <div class="wire-seg-val" id="diss-func">Request Response</div>
                        </div>
                        <div class="wire-seg">
                            <div class="wire-seg-label">Bitmap Hex &amp; Active DEs</div>
                            <div class="wire-seg-val" id="diss-bmp-hex">723800010E808000</div>
                        </div>
                    </div>

                    <label>Unpacked Bit-Matrix Presence Map</label>
                    <div id="dissector-bitmap-grid" class="bitmap-matrix-grid"></div>

                    <label style="margin-top: 12px;">Structured Wire Diagnostic Dump</label>
                    <pre class="ascii-dump" id="dissector-ascii-dump"></pre>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <h2 class="panel-title">Extracted Data Elements (DE 2 .. DE 128)</h2>
                        <span class="panel-tag" id="dissector-field-count">0 FIELDS PRESENT</span>
                    </div>
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>DE #</th>
                                    <th>Field Specification</th>
                                    <th>Encoding</th>
                                    <th>Max Len</th>
                                    <th>Unpacked Value</th>
                                    <th>PCI Masked View</th>
                                </tr>
                            </thead>
                            <tbody id="dissector-fields-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- ========================================================= -->
        <!-- TAB 3: LPM BIN ROUTING TABLE                              -->
        <!-- ========================================================= -->
        <section id="tab-routing" class="tab-pane">
            <div class="grid-routing">
                <!-- Left: Registered BIN Routes Table -->
                <div class="panel">
                    <div class="panel-header">
                        <h2 class="panel-title">Registered Longest-Prefix-Match (LPM) BIN Routes</h2>
                        <span class="panel-tag" id="routing-total-badge">3 ACTIVE + 1 DEFAULT</span>
                    </div>
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>BIN Prefix</th>
                                    <th>Prefix Len</th>
                                    <th>Destination Institution</th>
                                    <th>Socket Endpoint</th>
                                    <th>SLA Timeout</th>
                                    <th>Routing Tier</th>
                                </tr>
                            </thead>
                            <tbody id="routing-table-tbody"></tbody>
                        </table>
                    </div>
                </div>

                <!-- Right: LPM Route Tester + Add Route Form -->
                <div>
                    <div class="panel">
                        <div class="panel-header">
                            <h2 class="panel-title">Interactive LPM BIN Route Resolution Tester</h2>
                            <span class="panel-tag">PREFIX SCAN 8..1</span>
                        </div>

                        <label>Quick Card PAN Test Targets</label>
                        <div class="preset-group">
                            <button type="button" class="preset-chip" onclick="testLpmPanPreset('4143450089123456')">
                                <strong>4143450089123456</strong>Ecobank Visa BIN
                            </button>
                            <button type="button" class="preset-chip" onclick="testLpmPanPreset('5399830045678901')">
                                <strong>5399830045678901</strong>Stanbic MasterCard BIN
                            </button>
                            <button type="button" class="preset-chip" onclick="testLpmPanPreset('5041080077889900')">
                                <strong>5041080077889900</strong>GCB Gh-Link BIN
                            </button>
                            <button type="button" class="preset-chip" onclick="testLpmPanPreset('6061050011223344')">
                                <strong>6061050011223344</strong>Unregistered -> GhIPSS
                            </button>
                        </div>

                        <div class="form-row" style="grid-template-columns: 1fr auto; align-items: end;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="route-test-pan">Candidate Card PAN (DE 2)</label>
                                <input type="text" id="route-test-pan" value="4143450089123456" maxlength="19">
                            </div>
                            <button id="btn-test-route" type="button" class="btn btn-cyan" style="height: 35px;" onclick="evaluateLpmRoute()">
                                TEST LPM ROUTE MATCH
                            </button>
                        </div>

                        <div class="wire-segments" style="grid-template-columns: repeat(3, 1fr); margin-top: 12px;">
                            <div class="wire-seg">
                                <div class="wire-seg-label">Winning Prefix</div>
                                <div class="wire-seg-val" id="lpm-res-prefix">414345</div>
                            </div>
                            <div class="wire-seg">
                                <div class="wire-seg-label">Matched Institution</div>
                                <div class="wire-seg-val" id="lpm-res-dest">ECOBANK_GH</div>
                            </div>
                            <div class="wire-seg">
                                <div class="wire-seg-label">Upstream Socket</div>
                                <div class="wire-seg-val" id="lpm-res-socket">127.0.0.1:9001</div>
                            </div>
                        </div>

                        <div class="table-wrap" style="margin-top: 10px;">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Scan Len</th>
                                        <th>Candidate Prefix</th>
                                        <th>Table Lookup</th>
                                        <th>Resolution</th>
                                    </tr>
                                </thead>
                                <tbody id="lpm-trace-tbody"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="panel-header">
                            <h2 class="panel-title">Register New Institution BIN Prefix</h2>
                            <span class="panel-tag">POST /v1/routes</span>
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label for="new-route-bin">BIN Prefix (1-8 Digits)</label>
                                <input type="text" id="new-route-bin" value="458912" maxlength="8">
                            </div>
                            <div class="form-group">
                                <label for="new-route-dest">Destination Institution ID</label>
                                <input type="text" id="new-route-dest" value="FIDELITY_BANK_GH">
                            </div>
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label for="new-route-host">Target Host IP</label>
                                <input type="text" id="new-route-host" value="127.0.0.1">
                            </div>
                            <div class="form-group">
                                <label for="new-route-port">Target TCP Port</label>
                                <input type="number" id="new-route-port" value="9004">
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="new-route-timeout">Upstream SLA Timeout (ms)</label>
                            <input type="number" id="new-route-timeout" value="4500">
                        </div>
                        <button id="btn-add-route" type="button" class="btn btn-primary" style="width: 100%;" onclick="registerNewBinRoute()">
                            REGISTER LPM BIN ROUTE
                        </button>
                    </div>
                </div>
            </div>
        </section>

        <!-- ========================================================= -->
        <!-- TAB 4: 0420 SAF REVERSAL QUEUE & SETTLEMENT JOURNAL       -->
        <!-- ========================================================= -->
        <section id="tab-saf" class="tab-pane">
            <!-- SAF Queue Panel -->
            <div class="panel">
                <div class="panel-header">
                    <div>
                        <h2 class="panel-title">0420 Store-and-Forward (SAF) Reversal Queue</h2>
                        <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                            Asynchronous retry buffer for unacknowledged 0420 reversals embedding 42-digit DE 90 Original Data Elements
                        </span>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button id="btn-drain-saf" type="button" class="btn btn-amber" onclick="drainSafQueue()">
                            DRAIN SAF QUEUE
                        </button>
                        <button id="btn-run-eod" type="button" class="btn btn-cyan" onclick="runEodSettlement()">
                            RUN EOD SETTLEMENT CUTOVER
                        </button>
                    </div>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Reversal ID</th>
                                <th>Destination Bank</th>
                                <th>Orig MTI / STAN / RRN</th>
                                <th>Masked PAN</th>
                                <th>Amount</th>
                                <th>DE 90 Original Data Elements (42 Digits)</th>
                                <th>Retries</th>
                                <th>SAF State</th>
                            </tr>
                        </thead>
                        <tbody id="saf-queue-tbody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Switch Settlement & Transaction Journal -->
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title">Switch Authorization, Clearing &amp; Reversal Journal (SQLite WAL)</h2>
                    <span class="panel-tag" id="journal-count-badge">0 RECORDS</span>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>UTC Timestamp</th>
                                <th>Type</th>
                                <th>Req/Resp MTI</th>
                                <th>STAN / RRN</th>
                                <th>Masked Card PAN</th>
                                <th>Routed Bank</th>
                                <th>Amount</th>
                                <th>DE 39 / Auth</th>
                                <th>Latency</th>
                                <th>Status</th>
                                <th>Operator Action</th>
                            </tr>
                        </thead>
                        <tbody id="journal-tbody"></tbody>
                    </table>
                </div>
            </div>

            <!-- EOD Net Clearing Report -->
            <div class="panel" id="eod-settlement-panel">
                <div class="panel-header">
                    <h2 class="panel-title">End-of-Day (EOD) Multi-Bank Net Interbank Settlement Cutover</h2>
                    <span class="panel-tag" id="eod-batch-badge">BATCH: READY</span>
                </div>
                <div class="wire-segments">
                    <div class="wire-seg">
                        <div class="wire-seg-label">Gross Approved Volume</div>
                        <div class="wire-seg-val" id="eod-gross-val">GHS 0.00</div>
                    </div>
                    <div class="wire-seg">
                        <div class="wire-seg-label">0420 Reversal Volume</div>
                        <div class="wire-seg-val" id="eod-rev-val">GHS 0.00</div>
                    </div>
                    <div class="wire-seg">
                        <div class="wire-seg-label">Net Interbank Clearing</div>
                        <div class="wire-seg-val" id="eod-net-val">GHS 0.00</div>
                    </div>
                    <div class="wire-seg">
                        <div class="wire-seg-label">SHA-256 Clearing Batch Digest</div>
                        <div class="wire-seg-val" id="eod-hash-val">N/A</div>
                    </div>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Institution ID</th>
                                <th>Total Tx</th>
                                <th>Approved Count</th>
                                <th>0420 Reversals</th>
                                <th>Gross Volume (GHS)</th>
                                <th>Reversal Volume (GHS)</th>
                                <th>Net Settlement Position (GHS)</th>
                            </tr>
                        </thead>
                        <tbody id="eod-inst-tbody"></tbody>
                    </table>
                </div>
            </div>
        </section>

    </main>

    <script>
        const DE_SHORT_TAGS = {
            1: "BMP2", 2: "PAN", 3: "PROC", 4: "AMT", 7: "DT", 11: "STAN",
            12: "TIME", 13: "DATE", 14: "EXP", 18: "MCC", 22: "POSM", 25: "POSC",
            32: "ACQ", 37: "RRN", 38: "AUTH", 39: "RC", 41: "TID", 42: "MID",
            43: "LOC", 48: "PRIV", 49: "CCY", 54: "AAMT", 70: "NET", 90: "ORIG",
            102: "ACCT1", 103: "ACCT2", 128: "MAC"
        };

        let latestState = null;
        let lastWireHex = "";
        let sampleHexFrames = {
            "0210": "__SAMPLE_HEX_0210__",
            "0420": "__SAMPLE_HEX_0420__",
            "0800": "__SAMPLE_HEX_0800__"
        };

        function formatGhs(minor, ccy) {
            const val = (Number(minor || 0) / 100.0).toLocaleString('en-US', {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2
            });
            const label = (ccy === "840") ? "USD" : "GHS";
            return label + " " + val;
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            const pane = document.getElementById(tabId);
            if (pane) pane.classList.add('active');
            const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
            if (btn) btn.classList.add('active');
        }

        function renderBitmapMatrix(containerId, activeBitsList, hasSecondary) {
            const container = document.getElementById(containerId);
            if (!container) return;
            const totalBits = hasSecondary ? 128 : 64;
            const activeSet = new Set((activeBitsList || []).map(Number));
            let html = "";
            for (let b = 1; b <= totalBits; b++) {
                const isSet = activeSet.has(b);
                const tag = DE_SHORT_TAGS[b] || ("DE" + b);
                let cls = "bit-cell";
                if (isSet) {
                    cls += (b === 1) ? " active secondary-flag" : " active";
                }
                html += `
                    <div class="${cls}" title="Bit ${b} (${tag}): ${isSet ? 'PRESENT (1)' : 'ABSENT (0)'}">
                        <span class="bit-num">DE ${b}</span>
                        <span class="bit-val">${isSet ? '1' : '0'}</span>
                        <span class="bit-tag">${tag}</span>
                    </div>
                `;
            }
            container.innerHTML = html;
        }

        function selectBinPreset(pan, terminal, mcc, amount) {
            document.getElementById('sim-pan').value = pan;
            document.getElementById('sim-terminal').value = terminal;
            document.getElementById('sim-mcc').value = mcc;
            document.getElementById('sim-amount').value = amount;
            document.querySelectorAll('#tab-simulator .preset-chip').forEach(btn => {
                btn.classList.toggle('active', btn.textContent.includes(pan));
            });
        }

        async function dispatchTerminalTransaction() {
            const payload = {
                mti: document.getElementById('sim-mti').value,
                pan: document.getElementById('sim-pan').value.trim(),
                amount_minor: parseInt(document.getElementById('sim-amount').value || "10000", 10),
                currency_code: document.getElementById('sim-currency').value,
                mcc: document.getElementById('sim-mcc').value,
                terminal_id: document.getElementById('sim-terminal').value.trim() || "POS_AC01",
                merchant_id: document.getElementById('sim-merchant').value || "ACCRA_MALL_SUP "
            };

            const res = await fetch('/v1/switch/transact', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (!res.ok) {
                alert("Switch Transaction Error: " + (data.detail || "Invalid request"));
                return;
            }
            renderSimulatorResponse(data, payload);
            await refreshSwitchState();
        }

        function renderSimulatorResponse(data, reqPayload) {
            lastWireHex = data.wire_hex || "";
            sampleHexFrames["0210"] = lastWireHex;

            const routeMatch = data.route_match || {
                bin_prefix: "DEFAULT",
                destination_id: data.destination_institution || "GHIPSS_NATIONAL_SWITCH",
                endpoint: "127.0.0.1:9000"
            };
            const panStr = (reqPayload && reqPayload.pan) || (data.fields && data.fields["2"]) || "4143450000001234";
            const maskedPan = panStr.length >= 10 ? (panStr.slice(0, 6) + "******" + panStr.slice(-4)) : panStr;

            document.getElementById('hop-origin').textContent = `${(data.fields && data.fields["41"]) || "POS_AC01"} (MCC ${(data.fields && data.fields["18"]) || "5411"})`;
            document.getElementById('hop-req-mti').textContent = `MTI ${data.request_mti || "0200"} Inbound`;
            document.getElementById('hop-bin-prefix').textContent = `PREFIX: ${routeMatch.bin_prefix}`;
            document.getElementById('hop-pan-masked').textContent = maskedPan;
            document.getElementById('hop-dest-bank').textContent = data.destination_institution;
            document.getElementById('hop-dest-socket').textContent = routeMatch.endpoint;
            document.getElementById('hop-resp-status').textContent = `${data.mti} // RC ${data.response_code} ${data.status}`;
            document.getElementById('hop-resp-auth').textContent = `AUTH: ${data.auth_code || "ECHO"} | ${data.latency_ms || 0.35} ms`;

            const hasSec = Boolean(data.has_secondary_bitmap);
            document.getElementById('sim-bitmap-badge').textContent = hasSec
                ? `EXTENDED BITMAP: 128 BITS (${data.bitmap_hex})`
                : `PRIMARY BITMAP: 64 BITS (${data.bitmap_hex})`;

            renderBitmapMatrix('sim-bitmap-grid', data.active_bits || [], hasSec);

            const lenHex = lastWireHex.slice(0, 4).toUpperCase();
            const mtiHex = lastWireHex.slice(4, 12).toUpperCase();
            document.getElementById('wire-seg-len').textContent = `0x${lenHex} (${data.wire_bytes_length} Bytes)`;
            document.getElementById('wire-seg-mti').textContent = `${mtiHex} ("${data.mti}")`;
            document.getElementById('wire-seg-bmp').textContent = data.bitmap_hex || "N/A";
            document.getElementById('wire-seg-stan').textContent = `${data.stan || "000000"} / ${data.rrn || "N/A"}`;
            document.getElementById('sim-wire-hex').textContent = lastWireHex;

            const catalog = data.field_catalog || [];
            const tbody = document.getElementById('sim-de-tbody');
            tbody.innerHTML = catalog.map(f => `
                <tr>
                    <td><strong>DE ${f.de}</strong></td>
                    <td>${f.name}</td>
                    <td><span class="badge badge-info">${f.type}</span></td>
                    <td>${f.max_length}</td>
                    <td><code>${f.masked_value}</code></td>
                </tr>
            `).join('');
        }

        function sendCurrentWireToDissector() {
            if (lastWireHex) {
                document.getElementById('dissector-hex-input').value = lastWireHex;
                switchTab('tab-dissector');
                unpackHexWireFrame();
            }
        }

        async function loadSampleDissectorHex(kind) {
            let hex = sampleHexFrames[kind] || sampleHexFrames["0210"];
            document.getElementById('dissector-hex-input').value = hex;
            await unpackHexWireFrame();
        }

        async function unpackHexWireFrame() {
            const hexInput = document.getElementById('dissector-hex-input').value.trim();
            if (!hexInput) return;

            const res = await fetch('/v1/iso8583/unpack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hex_wire: hexInput })
            });
            const data = await res.json();
            if (!res.ok) {
                document.getElementById('dissector-status-msg').textContent = "Unpack Error: " + (data.detail || "Invalid frame");
                return;
            }

            document.getElementById('dissector-status-msg').textContent =
                `Decoded ${data.wire_bytes_length} wire bytes | Length Prefix: ${data.has_length_prefix ? 'YES (2B Big-Endian)' : 'NO'} | Active DEs: ${data.present_fields_count}`;
            document.getElementById('dissector-mti-badge').textContent = `MTI: ${data.mti}`;
            document.getElementById('diss-ver').textContent = data.mti_breakdown.version;
            document.getElementById('diss-class').textContent = data.mti_breakdown.class;
            document.getElementById('diss-func').textContent = `${data.mti_breakdown.function} (${data.mti_breakdown.origin})`;
            document.getElementById('diss-bmp-hex').textContent = data.bitmap_hex;
            document.getElementById('dissector-field-count').textContent = `${data.present_fields_count} FIELDS PRESENT`;
            document.getElementById('dissector-ascii-dump').textContent = data.dump;

            renderBitmapMatrix('dissector-bitmap-grid', data.active_bits || [], Boolean(data.has_secondary_bitmap));

            const tbody = document.getElementById('dissector-fields-tbody');
            tbody.innerHTML = (data.field_details || []).map(f => `
                <tr>
                    <td><strong>DE ${f.de}</strong></td>
                    <td>${f.name}</td>
                    <td><span class="badge badge-info">${f.type}</span></td>
                    <td>${f.max_length}</td>
                    <td><code>${f.value}</code></td>
                    <td><code>${f.masked_value}</code></td>
                </tr>
            `).join('');
        }

        function testLpmPanPreset(pan) {
            document.getElementById('route-test-pan').value = pan;
            evaluateLpmRoute();
        }

        async function evaluateLpmRoute() {
            const pan = document.getElementById('route-test-pan').value.trim();
            if (!pan) return;
            const res = await fetch('/v1/routes/match', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pan })
            });
            const data = await res.json();
            if (!res.ok) return;

            document.getElementById('lpm-res-prefix').textContent = data.matched_prefix;
            document.getElementById('lpm-res-dest').textContent = data.destination_id;
            document.getElementById('lpm-res-socket').textContent = `${data.host}:${data.port}`;

            const tbody = document.getElementById('lpm-trace-tbody');
            tbody.innerHTML = (data.lpm_trace || []).map(step => `
                <tr>
                    <td>Len ${step.prefix_length}</td>
                    <td><code>${step.candidate_prefix}</code></td>
                    <td>${step.destination_id}</td>
                    <td>
                        ${step.selected_winner
                            ? '<span class="badge badge-approved">LPM WINNER</span>'
                            : (step.matched ? '<span class="badge badge-info">SHADOW MATCH</span>' : '<span style="color: var(--text-muted);">MISS</span>')}
                    </td>
                </tr>
            `).join('') + (data.is_default_fallback ? `
                <tr>
                    <td>Fallback</td>
                    <td><code>DEFAULT</code></td>
                    <td>${data.destination_id}</td>
                    <td><span class="badge badge-reversed">DEFAULT SWITCH</span></td>
                </tr>
            ` : '');
        }

        async function registerNewBinRoute() {
            const payload = {
                bin_prefix: document.getElementById('new-route-bin').value.trim(),
                destination_id: document.getElementById('new-route-dest').value.trim(),
                host: document.getElementById('new-route-host').value.trim() || "127.0.0.1",
                port: parseInt(document.getElementById('new-route-port').value || "9004", 10),
                timeout_ms: parseInt(document.getElementById('new-route-timeout').value || "4500", 10)
            };
            const res = await fetch('/v1/routes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                document.getElementById('route-test-pan').value = payload.bin_prefix + "0011223344";
                await refreshSwitchState();
                await evaluateLpmRoute();
            }
        }

        async function triggerTransactionReversal(mti, stan, rrn, pan, amountMinor, ccy) {
            const res = await fetch('/v1/switch/reversal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    original_mti: mti || "0200",
                    original_stan: stan,
                    original_rrn: rrn,
                    pan: pan,
                    amount_minor: Number(amountMinor || 10000),
                    currency_code: ccy || "936"
                })
            });
            if (res.ok) {
                await refreshSwitchState();
                await runEodSettlement();
            }
        }

        async function drainSafQueue() {
            const res = await fetch('/v1/switch/saf/drain', { method: 'POST' });
            if (res.ok) {
                await refreshSwitchState();
            }
        }

        async function runEodSettlement() {
            const res = await fetch('/v1/switch/settlement/eod', { method: 'POST' });
            if (!res.ok) return;
            const data = await res.json();

            document.getElementById('eod-batch-badge').textContent = `BATCH: ${data.batch_id}`;
            document.getElementById('eod-gross-val').textContent = formatGhs(data.total_gross_minor, "936");
            document.getElementById('eod-rev-val').textContent = formatGhs(data.total_reversals_minor, "936");
            document.getElementById('eod-net-val').textContent = formatGhs(data.net_clearing_volume_minor, "936");
            document.getElementById('eod-hash-val').textContent = (data.clearing_hash || "").slice(0, 24) + "...";

            const tbody = document.getElementById('eod-inst-tbody');
            tbody.innerHTML = (data.institutions || []).map(inst => `
                <tr>
                    <td><strong>${inst.institution_id}</strong></td>
                    <td>${inst.total_transactions}</td>
                    <td>${inst.approved_count}</td>
                    <td>${inst.reversal_count}</td>
                    <td>${formatGhs(inst.gross_amount_minor, "936")}</td>
                    <td>${formatGhs(inst.reversal_amount_minor, "936")}</td>
                    <td><span class="badge badge-approved">${formatGhs(inst.net_settlement_minor, "936")}</span></td>
                </tr>
            `).join('');
        }

        function inspectJournalHex(hexStr) {
            document.getElementById('dissector-hex-input').value = hexStr;
            switchTab('tab-dissector');
            unpackHexWireFrame();
        }

        async function seedNetworkTraffic() {
            const btn = document.getElementById('btn-seed-traffic');
            if (btn) btn.setAttribute('data-seeded', 'pending');
            const res = await fetch('/v1/switch/bootstrap', { method: 'POST' });
            if (res.ok) {
                await refreshSwitchState();
                await runEodSettlement();
                if (btn) btn.setAttribute('data-seeded', 'true');
            }
        }

        async function refreshSwitchState() {
            const res = await fetch('/v1/switch/state');
            if (!res.ok) return;
            const state = await res.json();
            latestState = state;

            const t = state.telemetry;
            document.getElementById('kpi-processed').textContent = t.processed_count.toLocaleString();
            document.getElementById('kpi-approved').textContent = t.approved_count.toLocaleString();
            document.getElementById('kpi-reversals').textContent = t.reversals_count.toLocaleString();
            document.getElementById('kpi-saf-sub').textContent = `${t.saf_pending_count} Pending / ${t.saf_settled_count} Settled` + (t.saf_duplicates_suppressed > 0 ? ` / ${t.saf_duplicates_suppressed} Dup` : '');
            document.getElementById('kpi-routes').textContent = t.active_routes_count.toLocaleString();
            document.getElementById('kpi-volume').textContent = formatGhs(t.total_cleared_volume_minor, "936");
            document.getElementById('kpi-volume-sub').textContent = `Gross: ${formatGhs(t.gross_volume_minor, "936")}`;

            // Populate Routing Table
            const routes = state.routes || [];
            const defRoute = state.default_route;
            document.getElementById('routing-total-badge').textContent = `${routes.length} ACTIVE + 1 DEFAULT`;
            const routeRows = routes.map(r => `
                <tr>
                    <td><code>${r.bin_prefix}</code></td>
                    <td>${r.bin_prefix.length} digits</td>
                    <td><strong>${r.destination_id}</strong></td>
                    <td>${r.host}:${r.port}</td>
                    <td>${r.timeout_ms} ms</td>
                    <td><span class="badge badge-approved">ACTIVE_LPM</span></td>
                </tr>
            `);
            if (defRoute) {
                routeRows.push(`
                    <tr>
                        <td><code>${defRoute.bin_prefix}</code></td>
                        <td>Fallback</td>
                        <td><strong>${defRoute.destination_id}</strong></td>
                        <td>${defRoute.host}:${defRoute.port}</td>
                        <td>${defRoute.timeout_ms || 5000} ms</td>
                        <td><span class="badge badge-info">NATIONAL_SWITCH_FALLBACK</span></td>
                    </tr>
                `);
            }
            document.getElementById('routing-table-tbody').innerHTML = routeRows.join('');

            // Populate SAF Queue Table
            const safItems = state.saf_queue || [];
            const safTbody = document.getElementById('saf-queue-tbody');
            if (safItems.length === 0) {
                safTbody.innerHTML = `<tr><td colspan="8" style="color: var(--text-muted); text-align: center;">No 0420 Store-and-Forward reversals queued. Seed traffic or trigger a 0420 reversal below.</td></tr>`;
            } else {
                safTbody.innerHTML = safItems.map(s => `
                    <tr>
                        <td><code>${s.reversal_id}</code></td>
                        <td><strong>${s.destination_id}</strong></td>
                        <td>${s.original_mti} / ${s.original_stan} / ${s.original_rrn}</td>
                        <td><code>${s.pan_masked}</code></td>
                        <td>${formatGhs(s.amount_minor, s.currency_code)}</td>
                        <td><code>${s.de_90}</code></td>
                        <td>${s.retry_count} / ${s.max_retries}</td>
                        <td>
                            <span class="badge ${s.is_settled ? 'badge-approved' : 'badge-reversed'}">
                                ${s.status_label}
                            </span>
                        </td>
                    </tr>
                `).join('');
            }

            // Populate Settlement Journal Table
            const journal = state.journal || [];
            document.getElementById('journal-count-badge').textContent = `${journal.length} RECORDS`;
            const jTbody = document.getElementById('journal-tbody');
            if (journal.length === 0) {
                jTbody.innerHTML = `<tr><td colspan="11" style="color: var(--text-muted); text-align: center;">Journal empty. Click SEED LIVE NETWORK TRAFFIC or dispatch a frame.</td></tr>`;
            } else {
                jTbody.innerHTML = journal.map(j => {
                    const badgeCls = j.status === 'APPROVED' ? 'badge-approved' : (j.status === 'REVERSED' ? 'badge-reversed' : 'badge-declined');
                    const canReverse = j.status === 'APPROVED' && (j.request_mti === '0200' || j.request_mti === '0100');
                    const revItem = journal.find(r => r.request_mti === '0420' && r.rrn === j.rrn);
                    if (j.request_mti === '0420' && !sampleHexFrames["0420"]) {
                        sampleHexFrames["0420"] = j.request_wire_hex || j.wire_hex;
                    }
                    return `
                        <tr>
                            <td>${j.created_iso}</td>
                            <td><strong>${j.type}</strong></td>
                            <td><code>${j.request_mti} -> ${j.mti}</code></td>
                            <td>${j.stan} / ${j.rrn}</td>
                            <td><code>${j.pan_masked}</code></td>
                            <td><strong>${j.institution}</strong></td>
                            <td>${formatGhs(j.amount_minor, j.currency_code)}</td>
                            <td>RC ${j.response_code} / ${j.auth_code || 'N/A'}</td>
                            <td>${j.latency_ms} ms</td>
                            <td><span class="badge ${badgeCls}">${j.status}</span></td>
                            <td style="white-space: nowrap;">
                                ${canReverse && !revItem ? `
                                    <button type="button" class="btn btn-crimson btn-xs btn-trigger-reversal"
                                        onclick="triggerTransactionReversal('${j.request_mti}', '${j.stan}', '${j.rrn}', '${j.pan_raw}', ${j.amount_minor}, '${j.currency_code}')">
                                        TRIGGER 0420 REVERSAL
                                    </button>
                                ` : ''}
                                <button type="button" class="btn btn-secondary btn-xs" onclick="inspectJournalHex('${j.wire_hex}')">
                                    WIRE HEX
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            }
        }

        window.addEventListener('DOMContentLoaded', async () => {
            await refreshSwitchState();
            await dispatchTerminalTransaction();
            await evaluateLpmRoute();
            await runEodSettlement();
            if (lastWireHex) {
                document.getElementById('dissector-hex-input').value = lastWireHex;
                await unpackHexWireFrame();
            }
        });
    </script>
</body>
</html>
"""


def serve(host: str = "0.0.0.0", port: int = 8584):
    """Launch SwitchRail REST gateway service."""
    import uvicorn
    uvicorn.run("switchrail.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    serve()

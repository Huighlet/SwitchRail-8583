"""
SwitchRail-8583: High-Throughput Financial Transaction Switch REST & TCP Gateway.
Provides ISO 8583:1987 message encoding/decoding, Longest Prefix Match (LPM) BIN routing,
0420 SAF reversal dispatch, and interactive developer UI.
"""

from __future__ import annotations

import os
import struct
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from switchrail.message import ISO8583Message
from switchrail.routing import RouteEntry, RoutingTable
from switchrail.saf import StoreAndForwardQueue
from switchrail.switch import SwitchEngine
from switchrail.types import ResponseCode


# ---------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------

class TransactRequest(BaseModel):
    mti: str = Field("0200", description="Message Type Identifier: '0100' (Auth), '0200' (Purchase), '0420' (Reversal)")
    pan: str = Field(..., description="Primary Account Number (Card PAN), e.g. '4143450000001234'")
    amount_minor: int = Field(..., ge=1, description="Transaction amount in minor currency units (e.g. 50000 for 500.00 GHS)")
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


# ---------------------------------------------------------
# Switch Engine Initialization with Standard Routes
# ---------------------------------------------------------

app = FastAPI(
    title="SwitchRail-8583 Payment Switch",
    description="Core Banking ISO 8583:1987 / ISO 20022 Financial Transaction Switch with LPM BIN Routing and Store-and-Forward (SAF) Reversals.",
    version="1.0.0",
)

routing_table = RoutingTable()
routing_table.add_route(RouteEntry("414345", "ECOBANK_GH", "127.0.0.1", 9001))
routing_table.add_route(RouteEntry("539983", "STANBIC_GH", "127.0.0.1", 9002))
routing_table.add_route(RouteEntry("504108", "GCB_BANK", "127.0.0.1", 9003))
routing_table.default_route = RouteEntry("DEFAULT", "GHIPSS_NATIONAL_SWITCH", "127.0.0.1", 9000)

saf_queue = StoreAndForwardQueue()
engine = SwitchEngine(routing_table=routing_table, saf_queue=saf_queue)

_settlement_journal: List[Dict[str, Any]] = []
_journal_lock = threading.Lock()


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
# Developer UI Dashboard
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def switch_dashboard():
    """Interactive Payment Switch Dashboard & ISO 8583 Inspector."""
    routes_html = "".join(
        f"<tr><td><code>{r.bin_prefix}</code></td><td><strong>{r.destination_id}</strong></td><td>{r.host}:{r.port}</td><td>{r.timeout_ms}ms</td></tr>"
        for r in routing_table._routes.values()
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SwitchRail-8583 Core Banking Switch</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 32px; }}
            .container {{ max-width: 950px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            h1 {{ color: #10b981; margin-top: 0; font-size: 24px; font-weight: 600; }}
            p {{ color: #9ca3af; font-size: 14px; line-height: 1.5; }}
            .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }}
            .card {{ background: #1f2937; padding: 14px; border-radius: 6px; border-left: 3px solid #10b981; }}
            .card-label {{ font-size: 11px; text-transform: uppercase; color: #9ca3af; }}
            .card-val {{ font-size: 22px; font-weight: 700; color: #f9fafb; margin-top: 4px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
            th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #374151; }}
            th {{ background: #1f2937; color: #9ca3af; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
            .btn {{ display: inline-block; padding: 9px 16px; border-radius: 6px; background: #059669; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 600; margin-right: 8px; }}
            .btn:hover {{ background: #047857; }}
            code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; color: #6ee7b7; }}
            pre {{ background: #030712; padding: 14px; border-radius: 6px; color: #6ee7b7; font-size: 12px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SwitchRail-8583 Financial Transaction Switch</h1>
            <p>Institutional ISO 8583:1987 / ISO 20022 message processor, LPM card BIN router, and 0420 Store-and-Forward (SAF) reversal engine.</p>

            <div class="metrics">
                <div class="card">
                    <div class="card-label">Processed Inbound</div>
                    <div class="card-val">{engine.processed_count:,}</div>
                </div>
                <div class="card">
                    <div class="card-label">SAF Reversals</div>
                    <div class="card-val">{engine.reversals_triggered:,}</div>
                </div>
                <div class="card">
                    <div class="card-label">Active BIN Routes</div>
                    <div class="card-val">{len(routing_table._routes):,}</div>
                </div>
            </div>

            <p>
                <a href="/docs" class="btn">Explore OpenAPI / Swagger &rarr;</a>
                <a href="/v1/routes" class="btn" style="background: #374151;">View Registered BIN Routes</a>
            </p>

            <h3>Active LPM Routing Table (BIN Prefixes)</h3>
            <table>
                <thead>
                    <tr><th>BIN Prefix</th><th>Destination Institution</th><th>Socket Endpoint</th><th>Timeout</th></tr>
                </thead>
                <tbody>
                    {routes_html}
                </tbody>
            </table>

            <h3>Example Financial Transaction Ingestion (0200 Purchase)</h3>
            <pre>curl -X POST http://localhost:8584/v1/switch/transact \\
  -H "Content-Type: application/json" \\
  -d '{{
    "mti": "0200",
    "pan": "4143450000001234",
    "amount_minor": 50000,
    "currency_code": "936"
  }}'</pre>
        </div>
    </body>
    </html>
    """


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
        }
    return {"routes": routes, "default_route": default_r}


@app.post("/v1/routes", status_code=status.HTTP_201_CREATED)
def add_route(req: AddRouteRequest):
    """Register a new institution BIN route."""
    entry = RouteEntry(
        bin_prefix=req.bin_prefix,
        destination_id=req.destination_id,
        host=req.host,
        port=req.port,
        timeout_ms=req.timeout_ms,
    )
    routing_table.add_route(entry)
    return {"registered": True, "bin_prefix": req.bin_prefix, "destination_id": req.destination_id}


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
    execute LPM BIN routing, and return switch approval response with wire hex.
    """
    now = time.strftime("%m%d%H%M%S")
    stan = req.stan or f"{int(time.time()) % 1_000_000:06d}"
    # DE 37 (RRN) is fixed length 12: YYMMDD (6) + STAN (6)
    rrn = (req.rrn or f"{time.strftime('%y%m%d')}{stan}")[:12]
    amt_str = f"{req.amount_minor:012d}"

    # Build ISO 8583 Request Message
    iso_msg = ISO8583Message(mti=req.mti, is_binary_bitmap=True)
    iso_msg.set(2, req.pan)
    iso_msg.set(3, "000000")                   # Purchase
    iso_msg.set(4, amt_str)                    # Amount
    iso_msg.set(7, now)                        # Transmission Date/Time
    iso_msg.set(11, stan)                      # STAN
    iso_msg.set(12, now[4:10])                 # Local Time
    iso_msg.set(13, now[0:4])                  # Local Date
    iso_msg.set(18, req.mcc)                   # MCC
    iso_msg.set(32, req.pan[:6])               # Acquirer ID (BIN)
    iso_msg.set(37, rrn)                       # RRN
    iso_msg.set(41, (req.terminal_id or "TERM0001")[:8]) # Terminal ID (fixed 8 chars)
    iso_msg.set(42, (req.merchant_id or "MERC00000000001")[:15]) # Merchant ID (fixed 15 chars)
    iso_msg.set(49, req.currency_code)         # Currency

    # Match Route
    route = routing_table.match(req.pan)

    # Process through Switch Engine
    resp_msg = engine.process_inbound(iso_msg)

    # Pack into binary wire format
    wire_bytes = resp_msg.pack(include_length_prefix=True)

    fields_dict = {str(k): v for k, v in resp_msg.fields.items()}

    with _journal_lock:
        _settlement_journal.append({
            "type": "PURCHASE",
            "mti": req.mti,
            "institution": route.destination_id,
            "pan_masked": f"{req.pan[:6]}******{req.pan[-4:]}",
            "amount_minor": req.amount_minor,
            "currency_code": req.currency_code,
            "stan": stan,
            "rrn": rrn,
            "status": "APPROVED" if resp_msg.get(39) == ResponseCode.APPROVED.value else "DECLINED",
            "timestamp_ns": time.time_ns(),
        })

    return {
        "status": "APPROVED" if resp_msg.get(39) == ResponseCode.APPROVED.value else "DECLINED",
        "mti": resp_msg.mti,
        "response_code": resp_msg.get(39),
        "stan": resp_msg.get(11),
        "rrn": resp_msg.get(37),
        "auth_code": resp_msg.get(38),
        "destination_institution": route.destination_id,
        "wire_bytes_length": len(wire_bytes),
        "wire_hex": wire_bytes.hex(),
        "fields": fields_dict,
    }


@app.post("/v1/switch/reversal")
def process_reversal(req: ReversalRequest):
    """
    Ingest a 0420 Reversal Advice with original transaction audit trail (DE 90).
    Enqueues to SAF and returns 0430 Reversal Response.
    """
    now = time.strftime("%m%d%H%M%S")
    stan = f"{int(time.time()) % 1_000_000:06d}"
    amt_str = f"{req.amount_minor:012d}"

    # Construct DE 90 Original Data Elements (Audit trail linking reversal to original transaction)
    # DE 90 Format: Numeric 42 chars
    de_90 = f"{req.original_mti}{req.original_stan.zfill(6)}{now}{req.pan[:6].zfill(11)}".zfill(42)

    iso_msg = ISO8583Message(mti="0420", is_binary_bitmap=True)
    iso_msg.set(2, req.pan)
    iso_msg.set(3, "000000")
    iso_msg.set(4, amt_str)
    iso_msg.set(7, now)
    iso_msg.set(11, stan)
    iso_msg.set(37, req.original_rrn)
    iso_msg.set(39, ResponseCode.SUSPECTED_FRAUD.value)
    iso_msg.set(49, req.currency_code)
    iso_msg.set(90, de_90)

    route = routing_table.match(req.pan)
    resp_msg = engine.process_inbound(iso_msg)
    wire_bytes = resp_msg.pack(include_length_prefix=True)

    with _journal_lock:
        _settlement_journal.append({
            "type": "REVERSAL",
            "mti": "0420",
            "institution": route.destination_id,
            "pan_masked": f"{req.pan[:6]}******{req.pan[-4:]}",
            "amount_minor": req.amount_minor,
            "currency_code": req.currency_code,
            "stan": stan,
            "rrn": req.original_rrn,
            "status": "REVERSED",
            "timestamp_ns": time.time_ns(),
        })

    return {
        "status": "REVERSED",
        "mti": resp_msg.mti,
        "response_code": resp_msg.get(39),
        "stan": resp_msg.get(11),
        "rrn": resp_msg.get(37),
        "destination_institution": route.destination_id,
        "original_de_90": de_90,
        "wire_hex": wire_bytes.hex(),
    }


@app.post("/v1/iso8583/unpack")
def unpack_hex(req: HexUnpackRequest):
    """
    Unpack raw hex-encoded ISO 8583 bytes into structured field breakdown.
    """
    clean_hex = req.hex_wire.strip().replace(" ", "").replace("\n", "")
    try:
        data = bytes.fromhex(clean_hex)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}")

    has_prefix = len(data) > 6 and data[0:2] == struct.pack(">H", len(data) - 2)

    try:
        msg = ISO8583Message.unpack(data, has_length_prefix=has_prefix, is_binary_bitmap=True)
        return {
            "mti": msg.mti,
            "has_length_prefix": has_prefix,
            "present_fields_count": len(msg.fields),
            "present_fields": sorted(list(msg.fields.keys())),
            "fields": {str(k): v for k, v in msg.fields.items()},
            "dump": msg.dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"ISO 8583 unpacking error: {e}")


@app.post("/v1/switch/settlement/eod", tags=["Settlement"])
def export_settlement_eod() -> Dict[str, Any]:
    """Generate End-of-Day Cutover & Net Interbank Settlement report."""
    import hashlib
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


def serve(host: str = "0.0.0.0", port: int = 8584):
    """Launch SwitchRail REST gateway service."""
    import uvicorn
    uvicorn.run("switchrail.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    serve()

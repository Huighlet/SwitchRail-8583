"""
SwitchRail Client SDK: Idiomatic high-performance client for the SwitchRail-8583 Payment Switch.
Supports ISO 8583:1987 transaction routing, automated 0420 reversals, and EOD settlement cutover.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


class SwitchRailClient:
    """
    Client for interacting with a live SwitchRail-8583 payment switch instance.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8584",
        api_key: Optional[str] = None,
        timeout_seconds: float = 10.0,
        http_client: Optional[Any] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        if http_client is not None:
            self._client = http_client
        elif httpx is not None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        else:
            self._client = None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> SwitchRailClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def transact(
        self,
        pan: str,
        amount_minor: int,
        currency_code: str = "936",
        mti: str = "0200",
        stan: Optional[str] = None,
        rrn: Optional[str] = None,
        mcc: str = "5411",
        terminal_id: str = "POS_0001",
        merchant_id: str = "MERC_ACCRA_001 ",
    ) -> Dict[str, Any]:
        """
        Authorize or execute a card transaction via ISO 8583 switch.
        """
        payload = {
            "mti": mti,
            "pan": pan,
            "amount_minor": amount_minor,
            "currency_code": currency_code,
            "stan": stan,
            "rrn": rrn,
            "mcc": mcc,
            "terminal_id": terminal_id,
            "merchant_id": merchant_id,
        }
        resp = self._client.post("/v1/switch/transact", json=payload)
        resp.raise_for_status()
        return resp.json()

    def reverse(
        self,
        original_mti: str,
        original_stan: str,
        original_rrn: str,
        pan: str,
        amount_minor: int,
        currency_code: str = "936",
    ) -> Dict[str, Any]:
        """
        Submit a 0420 Reversal Advice with DE 90 audit trail.
        """
        payload = {
            "original_mti": original_mti,
            "original_stan": original_stan,
            "original_rrn": original_rrn,
            "pan": pan,
            "amount_minor": amount_minor,
            "currency_code": currency_code,
        }
        resp = self._client.post("/v1/switch/reversal", json=payload)
        resp.raise_for_status()
        return resp.json()

    def unpack_hex(self, hex_wire: str) -> Dict[str, Any]:
        """Unpack raw binary ISO 8583 wire frame into structured dictionary."""
        resp = self._client.post("/v1/iso8583/unpack", json={"hex_wire": hex_wire})
        resp.raise_for_status()
        return resp.json()

    def get_metrics(self) -> str:
        """Fetch Prometheus metrics."""
        resp = self._client.get("/metrics")
        resp.raise_for_status()
        return resp.text

    def export_settlement_eod(self) -> Dict[str, Any]:
        """Trigger End-of-Day Cutover and receive multi-bank net settlement file."""
        resp = self._client.post("/v1/switch/settlement/eod")
        resp.raise_for_status()
        return resp.json()

    def get_saf_pending(self) -> Dict[str, Any]:
        """Query pending Store-and-Forward reversals."""
        resp = self._client.get("/v1/switch/saf/pending")
        resp.raise_for_status()
        return resp.json()

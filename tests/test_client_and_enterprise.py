"""
Enterprise and Client SDK tests for SwitchRail-8583.
Validates Pillar 1 (Enterprise Middleware & Metrics), Pillar 2 (EOD Settlement Cutover), and Pillar 3 (Client SDK).
"""

import pytest
from starlette.testclient import TestClient

from switchrail import server
from switchrail.client import SwitchRailClient


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(server.app)


def test_prometheus_metrics_endpoint(test_client: TestClient):
    resp = test_client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "switchrail_transactions_total" in text
    assert "switchrail_saf_depth" in text
    assert "switchrail_routes_active" in text


def test_eod_settlement_cutover(test_client: TestClient):
    # 1. Post a transaction
    tx_resp = test_client.post("/v1/switch/transact", json={
        "mti": "0200",
        "pan": "4143450000009999",
        "amount_minor": 50000,
        "currency_code": "936",
    })
    assert tx_resp.status_code == 200

    # 2. Trigger EOD settlement
    settle_resp = test_client.post("/v1/switch/settlement/eod")
    assert settle_resp.status_code == 200
    data = settle_resp.json()
    assert data["status"] == "SETTLED"
    assert "batch_id" in data
    assert "clearing_hash" in data
    assert data["total_records_processed"] >= 1
    assert data["net_clearing_volume_minor"] >= 50000


def test_saf_pending_endpoint(test_client: TestClient):
    resp = test_client.get("/v1/switch/saf/pending")
    assert resp.status_code == 200
    data = resp.json()
    assert "pending_count" in data


def test_switchrail_python_client_sdk(test_client: TestClient):
    client = SwitchRailClient(http_client=test_client)

    # 1. Transact
    auth = client.transact(
        pan="5399831111222233",
        amount_minor=12500,
        currency_code="936",
        terminal_id="POS_AIRPORT",
    )
    assert auth["status"] == "APPROVED"
    assert auth["destination_institution"] == "STANBIC_GH"
    stan = auth["stan"]
    rrn = auth["rrn"]

    # 2. Reverse
    rev = client.reverse(
        original_mti="0200",
        original_stan=stan,
        original_rrn=rrn,
        pan="5399831111222233",
        amount_minor=12500,
        currency_code="936",
    )
    assert rev["status"] == "REVERSED"
    assert "original_de_90" in rev

    # 3. Settlement Cutover via SDK
    settle = client.export_settlement_eod()
    assert settle["status"] == "SETTLED"
    client.close()

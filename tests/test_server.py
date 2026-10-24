"""
Unit & Integration Tests for SwitchRail-8583 REST API Gateway.
"""

import pytest
from starlette.testclient import TestClient
from switchrail.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "processed_count" in data


def test_dashboard_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "SwitchRail-8583 Financial Transaction Switch" in response.text


def test_routes_endpoints(client):
    # 1. Query routes
    routes_resp = client.get("/v1/routes")
    assert routes_resp.status_code == 200
    data = routes_resp.json()
    assert len(data["routes"]) >= 3

    # 2. Add custom BIN route
    add_resp = client.post("/v1/routes", json={
        "bin_prefix": "424242",
        "destination_id": "TEST_CARD_NETWORK",
        "host": "127.0.0.1",
        "port": 9999,
        "timeout_ms": 3000,
    })
    assert add_resp.status_code == 201
    assert add_resp.json()["registered"] is True


def test_transact_purchase_success(client):
    req_data = {
        "mti": "0200",
        "pan": "4143450000001234",
        "amount_minor": 25000,
        "currency_code": "936",
    }
    resp = client.post("/v1/switch/transact", json=req_data)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "APPROVED"
    assert data["mti"] == "0210"
    assert data["response_code"] == "00"
    assert data["destination_institution"] == "ECOBANK_GH"
    assert "wire_hex" in data
    assert len(data["wire_hex"]) > 0


def test_reversal_advice(client):
    reversal_data = {
        "original_mti": "0200",
        "original_stan": "000123",
        "original_rrn": "261024000123",
        "pan": "5399830000005678",
        "amount_minor": 15000,
        "currency_code": "936",
    }
    resp = client.post("/v1/switch/reversal", json=reversal_data)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "REVERSED"
    assert data["mti"] == "0430"
    assert data["response_code"] == "00"
    assert data["destination_institution"] == "STANBIC_GH"


def test_unpack_hex_wire(client):
    # First generate a valid wire packet via transact
    resp = client.post("/v1/switch/transact", json={
        "mti": "0100",
        "pan": "5041080000009999",
        "amount_minor": 10000,
        "currency_code": "936",
    })
    wire_hex = resp.json()["wire_hex"]

    # Now unpack that hex
    unpack_resp = client.post("/v1/iso8583/unpack", json={"hex_wire": wire_hex})
    assert unpack_resp.status_code == 200
    unpack_data = unpack_resp.json()
    assert unpack_data["mti"] == "0110"
    assert "present_fields" in unpack_data
    assert "39" in unpack_data["fields"]  # Response Code

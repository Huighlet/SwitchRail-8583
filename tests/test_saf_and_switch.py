"""
Unit tests for the Switch Engine and Store-and-Forward (SAF) Reversal Queue.
"""

import time
import pytest

from switchrail.message import ISO8583Message
from switchrail.routing import RouteEntry, RoutingTable
from switchrail.saf import StoreAndForwardQueue
from switchrail.switch import SwitchEngine
from switchrail.types import NetworkManagementCode, ResponseCode, SwitchTimeoutError


def test_switch_handles_0800_echo():
    """Verify switch immediately responds to 0800 Network Management."""
    engine = SwitchEngine()
    echo = ISO8583Message(mti="0800")
    echo.set(70, NetworkManagementCode.ECHO_TEST)
    echo.set(11, "000001")

    resp = engine.process_inbound(echo)
    assert resp.mti == "0810"
    assert resp.get(39) == ResponseCode.APPROVED
    assert resp.get(70) == NetworkManagementCode.ECHO_TEST
    assert engine.processed_count == 1


def test_switch_handles_0200_successful_dispatch():
    """Verify switch dispatches 0200 to registered issuer and returns 0210."""
    routing = RoutingTable()
    routing.add_route(RouteEntry("414345", "ECOBANK_GH", "127.0.0.1", 9001))
    engine = SwitchEngine(routing_table=routing)

    # Dispatcher mock that approves transactions < 500 GHS
    def mock_issuer(route: RouteEntry, req: ISO8583Message) -> ISO8583Message:
        return req.build_response(ResponseCode.APPROVED)

    engine.set_dispatcher(mock_issuer)

    tx = ISO8583Message(mti="0200")
    tx.set(2, "4143451234567890")
    tx.set(3, "000000")
    tx.set(4, "000000025000")  # 250.00 GHS
    tx.set(11, "000123")
    tx.set(37, "202610240001")

    resp = engine.process_inbound(tx)
    assert resp.mti == "0210"
    assert resp.get(39) == ResponseCode.APPROVED
    assert engine.reversals_triggered == 0


def test_switch_triggers_saf_reversal_on_timeout():
    """Verify switch automatically generates 0420 Store-and-Forward Reversal when issuer times out."""
    routing = RoutingTable()
    routing.add_route(RouteEntry("539983", "STANBIC_GH", "127.0.0.1", 9002))
    saf = StoreAndForwardQueue()
    engine = SwitchEngine(routing_table=routing, saf_queue=saf)

    # Dispatcher mock that simulates an upstream network timeout
    def timeout_dispatcher(route: RouteEntry, req: ISO8583Message) -> ISO8583Message:
        raise SwitchTimeoutError("Issuer connection timed out after 5000ms")

    engine.set_dispatcher(timeout_dispatcher)

    tx = ISO8583Message(mti="0200")
    tx.set(2, "5399831122334455")
    tx.set(3, "010000")          # ATM Withdrawal
    tx.set(4, "000000050000")
    tx.set(11, "000999")
    tx.set(37, "RRN_TIMED_OUT")

    # Inbound call
    resp = engine.process_inbound(tx)

    # 1. Acquirer must receive 0210 with Timeout Response Code (91)
    assert resp.mti == "0210"
    assert resp.get(39) == ResponseCode.TIMEOUT_REVERSAL

    # 2. Switch must increment reversals_triggered
    assert engine.reversals_triggered == 1

    # 3. Reversal must be safely parked in the Store-and-Forward queue
    assert saf.pending_count() == 1
    due = saf.get_due_reversals()
    assert len(due) == 1
    assert due[0].reversal_message.mti == "0420"
    assert due[0].destination_id == "STANBIC_GH"


def test_saf_exponential_backoff_and_acknowledgement():
    """Verify Store-and-Forward queue exponential backoff retry and resolution."""
    saf = StoreAndForwardQueue(initial_backoff_sec=0.1, backoff_multiplier=2.0)
    rev_msg = ISO8583Message(mti="0420")
    rev_msg.set(11, "000555")

    rec = saf.enqueue_reversal("rev_000555", "DEST_GCB", rev_msg, max_retries=3)
    assert saf.pending_count() == 1

    # First attempt fails
    saf.record_attempt_failure("rev_000555")
    assert rec.retry_count == 1
    # Next attempt is delayed
    assert len(saf.get_due_reversals()) == 0

    # Wait for delay
    time.sleep(0.12)
    assert len(saf.get_due_reversals()) == 1

    # Successful acknowledgment (e.g. 0430 response received)
    saf.acknowledge_success("rev_000555")
    assert saf.pending_count() == 0

"""
SwitchRail-8583 Payment Switch Engine.
Coordinates ISO 8583 transaction switching, route dispatching,
timeout reversal escalation, and network management echoing.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, Optional

from switchrail.message import ISO8583Message
from switchrail.routing import RouteEntry, RoutingTable
from switchrail.saf import StoreAndForwardQueue
from switchrail.types import ResponseCode, RoutingError, SwitchTimeoutError


class SwitchEngine:
    """
    High-Throughput ISO 8583 Financial Transaction Switch.
    """
    def __init__(
        self,
        routing_table: Optional[RoutingTable] = None,
        saf_queue: Optional[StoreAndForwardQueue] = None,
    ) -> None:
        self.routing_table = routing_table or RoutingTable()
        self.saf_queue = saf_queue or StoreAndForwardQueue()
        self._issuer_dispatcher: Optional[Callable[[RouteEntry, ISO8583Message], ISO8583Message]] = None
        self._processed_count: int = 0
        self._reversals_triggered: int = 0

    @property
    def processed_count(self) -> int:
        return self._processed_count

    @property
    def reversals_triggered(self) -> int:
        return self._reversals_triggered

    def set_dispatcher(self, dispatcher: Callable[[RouteEntry, ISO8583Message], ISO8583Message]) -> None:
        """Register synchronous or async issuer dispatch handler."""
        self._issuer_dispatcher = dispatcher

    def process_inbound(self, request: ISO8583Message) -> ISO8583Message:
        """
        Process an inbound ISO 8583 message arriving from an Acquirer (ATM/POS/Mobile Agent).
        Returns the corresponding response message.
        """
        self._processed_count += 1
        mti = request.mti

        # 1. Network Management (0800 -> 0810)
        if mti == "0800":
            return self._handle_network_management(request)

        # 2. Reversal Advice (0420 -> 0430)
        elif mti == "0420":
            return self._handle_reversal_advice(request)

        # 3. Financial Transaction Request (0200 -> 0210)
        elif mti == "0200":
            return self._handle_financial_transaction(request)

        # 4. Authorization Request (0100 -> 0110)
        elif mti == "0100":
            return self._handle_authorization(request)

        # Unhandled MTI
        resp = request.build_response(response_code=ResponseCode.INVALID_TRANSACTION)
        return resp

    def _handle_network_management(self, msg: ISO8583Message) -> ISO8583Message:
        """Echo tests and sign-on handshakes (0800 -> 0810)."""
        resp = msg.build_response(response_code=ResponseCode.APPROVED)
        if msg.has(70):
            resp.set(70, msg.get(70))
        return resp

    def _handle_reversal_advice(self, msg: ISO8583Message) -> ISO8583Message:
        """Acquirer Reversal Advice (0420 -> 0430)."""
        stan = msg.get(11, "000000")
        rrn = msg.get(37, "000000000000")
        reversal_id = f"rev_{stan}_{rrn}"

        # If this reversal was queued in SAF, acknowledge and remove it
        self.saf_queue.acknowledge_success(reversal_id)

        resp = msg.build_response(response_code=ResponseCode.APPROVED)
        return resp

    def _handle_financial_transaction(self, request: ISO8583Message) -> ISO8583Message:
        """Process 0200 Purchase / Withdrawal / Transfer."""
        pan = request.get(2)
        if not pan:
            return request.build_response(response_code=ResponseCode.INVALID_CARD_NUMBER)

        # Match destination issuer route
        try:
            route = self.routing_table.match(pan)
        except RoutingError:
            return request.build_response(response_code=ResponseCode.RESTRICTED_CARD)

        # Dispatch to Issuer
        try:
            if self._issuer_dispatcher is not None:
                issuer_response = self._issuer_dispatcher(route, request)
                return issuer_response
            else:
                # Default mock approval if no external dispatcher registered
                return request.build_response(response_code=ResponseCode.APPROVED)

        except SwitchTimeoutError:
            # Issuer timed out: trigger automated Store-and-Forward Reversal
            self._reversals_triggered += 1
            stan = request.get(11, "000000")
            rrn = request.get(37, "000000000000")
            reversal_id = f"rev_{stan}_{rrn}"

            reversal_msg = request.build_reversal(reason_code=ResponseCode.TIMEOUT_REVERSAL)
            self.saf_queue.enqueue_reversal(
                reversal_id=reversal_id,
                destination_id=route.destination_id,
                reversal_message=reversal_msg,
            )

            # Return Timeout / Issuer inoperative code to Acquirer
            return request.build_response(response_code=ResponseCode.TIMEOUT_REVERSAL)

    def _handle_authorization(self, request: ISO8583Message) -> ISO8583Message:
        """Process 0100 Card Pre-Authorization."""
        pan = request.get(2)
        if not pan:
            return request.build_response(response_code=ResponseCode.INVALID_CARD_NUMBER)

        try:
            route = self.routing_table.match(pan)
        except RoutingError:
            return request.build_response(response_code=ResponseCode.RESTRICTED_CARD)

        if self._issuer_dispatcher is not None:
            return self._issuer_dispatcher(route, request)
        return request.build_response(response_code=ResponseCode.APPROVED)

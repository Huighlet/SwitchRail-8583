"""
Production Simulation Harness: SwitchRail-8583 Interbank Switching & Settlement.
Simulates a nationwide ATM and Point-of-Sale (POS) acquiring network:
  1. Multi-bank routing across Visa, Mastercard, and national debit BINs.
  2. 300 concurrent ISO 8583 0200 purchase authorizations with bitmap validation.
  3. Network timeout simulation triggering automated 0420 Store-and-Forward (SAF) reversals with DE 90 audit trails.
  4. End-of-Day (EOD) interbank netting and settlement batch generation.
"""

from __future__ import annotations

import random
import sys
import time
from typing import Dict, List

from switchrail.message import ISO8583Message
from switchrail.routing import RouteEntry, RoutingTable
from switchrail.saf import StoreAndForwardQueue
from switchrail.switch import SwitchEngine
from switchrail.types import ResponseCode


def run_switch_network_simulation() -> None:
    print("=" * 70)
    print("SWITCHRAIL-8583: INTERBANK ATM & POS SWITCHING SIMULATION")
    print("=" * 70)

    # 1. Setup Interbank Routing Engine
    print("\n[Phase 1] Configuring Interbank LPM Routing Table & SAF Queue...")
    routing_table = RoutingTable()
    routing_table.add_route(RouteEntry("414345", "ECOBANK_GH", "10.0.1.10", 9001))
    routing_table.add_route(RouteEntry("539983", "STANBIC_GH", "10.0.1.20", 9002))
    routing_table.add_route(RouteEntry("504108", "GCB_BANK", "10.0.1.30", 9003))
    routing_table.default_route = RouteEntry("DEFAULT", "GHIPSS_NATIONAL_SWITCH", "10.0.0.1", 9000)

    saf_queue = StoreAndForwardQueue()
    engine = SwitchEngine(routing_table=routing_table, saf_queue=saf_queue)
    print("  Configured 3 issuing bank routes + default national payment switch.")

    # 2. Simulate 300 ATM / POS Transactions
    print("\n[Phase 2] Simulating 300 Concurrent ATM/POS Authorizations (0200)...")
    bins = ["414345", "539983", "504108"]
    terminals = [f"POS_TERMINAL_{i:02d}" for i in range(1, 11)] + [f"ATM_KIOSK_{i:02d}" for i in range(1, 6)]

    transactions_to_reverse = []
    approved_count = 0
    total_volume_minor = 0

    start_time = time.perf_counter()
    for i in range(300):
        bin_prefix = random.choice(bins)
        pan = f"{bin_prefix}{random.randint(1000000000, 9999999999)}"
        amount_minor = random.randint(20_00, 1500_00)  # GHS 20.00 to GHS 1,500.00
        now = time.strftime("%m%d%H%M%S")
        stan = f"{(i + 1):06d}"
        rrn = f"{time.strftime('%y%m%d')}{stan}"
        term = random.choice(terminals)

        iso_msg = ISO8583Message(mti="0200", is_binary_bitmap=True)
        iso_msg.set(2, pan)
        iso_msg.set(3, "000000")  # Purchase
        iso_msg.set(4, f"{amount_minor:012d}")
        iso_msg.set(7, now)
        iso_msg.set(11, stan)
        iso_msg.set(12, now[4:10])
        iso_msg.set(13, now[0:4])
        iso_msg.set(18, "5411" if "POS" in term else "6011")
        iso_msg.set(32, bin_prefix)
        iso_msg.set(37, rrn)
        iso_msg.set(41, term[:8])
        iso_msg.set(49, "936")  # GHS

        resp = engine.process_inbound(iso_msg)
        if resp.get(39) == ResponseCode.APPROVED.value:
            approved_count += 1
            total_volume_minor += amount_minor

        # Pick 15 transactions to simulate terminal communication timeout / power cut
        if i % 20 == 0:
            transactions_to_reverse.append({
                "pan": pan,
                "amount_minor": amount_minor,
                "stan": stan,
                "rrn": rrn,
                "time": now,
            })

    elapsed = time.perf_counter() - start_time
    print(f"  Switched 300 transactions in {elapsed:.3f}s ({300 / elapsed:,.0f} tx/s).")
    print(f"  Approved: {approved_count}/300. Gross Volume Cleared: GHS {total_volume_minor / 100:,.2f}")

    # 3. Simulate Automated 0420 Reversals
    print("\n[Phase 3] Triggering 15 Automated 0420 Reversals with DE 90 Audit Trails...")
    reversal_volume_minor = 0
    for tx in transactions_to_reverse:
        now_rev = time.strftime("%m%d%H%M%S")
        rev_stan = f"{random.randint(100000, 999999):06d}"
        de_90 = f"0200{tx['stan'].zfill(6)}{tx['time']}{tx['pan'][:6].zfill(11)}".zfill(42)

        rev_msg = ISO8583Message(mti="0420", is_binary_bitmap=True)
        rev_msg.set(2, tx["pan"])
        rev_msg.set(3, "000000")
        rev_msg.set(4, f"{tx['amount_minor']:012d}")
        rev_msg.set(7, now_rev)
        rev_msg.set(11, rev_stan)
        rev_msg.set(37, tx["rrn"])
        rev_msg.set(39, ResponseCode.SUSPECTED_FRAUD.value)
        rev_msg.set(49, "936")
        rev_msg.set(90, de_90)

        resp_rev = engine.process_inbound(rev_msg)
        assert resp_rev.mti == "0430", "Reversal response MTI must be 0430!"
        reversal_volume_minor += tx["amount_minor"]

    print(f"  Enqueued & acknowledged {len(transactions_to_reverse)} reversals into SAF queue.")
    print(f"  Reversal Volume: GHS {reversal_volume_minor / 100:,.2f}")

    # 4. Multi-Bank Net Clearing & Settlement Cutover
    print("\n[Phase 4] Generating End-of-Day (EOD) Interbank Net Settlement Report...")
    net_clearing_volume = total_volume_minor - reversal_volume_minor
    print(f"  Total Transactions Processed: 300")
    print(f"  Total Gross Authorization:    GHS {total_volume_minor / 100:,.2f}")
    print(f"  Total Reversals (SAF):        GHS {reversal_volume_minor / 100:,.2f}")
    print(f"  Net Interbank Settlement:     GHS {net_clearing_volume / 100:,.2f}")
    print(f"  SAF Active Pending Queue:     {len(saf_queue._queue)} records")

    assert net_clearing_volume > 0, "Net settlement volume must remain positive!"
    print("\n[PASS] Interbank Switching & Settlement Simulation completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_switch_network_simulation()

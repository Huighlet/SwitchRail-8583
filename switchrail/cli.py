"""
SwitchRail-8583 CLI: Utilities for Message Packing, Hex Inspection, Benchmarks, and Mock Switch Server.
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import struct
import sys
import time

from switchrail.message import ISO8583Message
from switchrail.routing import RouteEntry, RoutingTable
from switchrail.switch import SwitchEngine
from switchrail.types import NetworkManagementCode, ResponseCode


def cmd_unpack_hex(hex_str: str) -> None:
    """Decode raw hex wire bytes and display message dump."""
    clean_hex = hex_str.strip().replace(" ", "").replace("\n", "")
    data = bytes.fromhex(clean_hex)
    has_length_prefix = len(data) > 6 and data[0:2] == struct.pack(">H", len(data) - 2)

    msg = ISO8583Message.unpack(data, has_length_prefix=has_length_prefix, is_binary_bitmap=True)
    print(msg.dump())


def cmd_bench(count: int = 50_000) -> None:
    """Benchmark ISO 8583 message packing and unpacking throughput."""
    print("=" * 60)
    print(f"SWITCHRAIL-8583 BENCHMARK: {count:,} MESSAGES")
    print("=" * 60)

    # Construct standard 0200 Financial Transaction
    msg = ISO8583Message(mti="0200", is_binary_bitmap=True)
    msg.set(2, "4143450000001234")               # Ecobank Ghana Visa PAN
    msg.set(3, "000000")                         # Purchase Goods & Services
    msg.set(4, "000000050000")                   # 500.00 GHS (50,000 pesewas)
    msg.set(7, "1024063000")                     # Transmission Date/Time (MMDDhhmmss)
    msg.set(11, "000123")                        # STAN
    msg.set(12, "063000")                        # Local Time
    msg.set(13, "1024")                          # Local Date
    msg.set(14, "2812")                          # Expiry Date (YYMM)
    msg.set(18, "5411")                          # Grocery Store MCC
    msg.set(22, "051")                           # Chip Card + PIN
    msg.set(25, "00")                            # Normal condition
    msg.set(32, "414345")                        # Acquirer ID
    msg.set(37, "202610240123")                  # RRN
    msg.set(41, "POS_0001")                      # TID
    msg.set(42, "MERC_ACCRA_001 ")               # MID
    msg.set(43, "SHOPRITE ACCRA MALL GH")        # Card Acceptor Name
    msg.set(49, "936")                           # Currency (GHS)

    # 1. Benchmark Packing
    t0 = time.perf_counter()
    packed_bytes = None
    for _ in range(count):
        packed_bytes = msg.pack(include_length_prefix=True)
    t_pack = time.perf_counter() - t0
    pack_tps = count / t_pack

    assert packed_bytes is not None

    # 2. Benchmark Unpacking
    t0 = time.perf_counter()
    for _ in range(count):
        _ = ISO8583Message.unpack(packed_bytes, has_length_prefix=True, is_binary_bitmap=True)
    t_unpack = time.perf_counter() - t0
    unpack_tps = count / t_unpack

    # 3. Benchmark Full Cycle (Pack + Unpack + Build Response)
    t0 = time.perf_counter()
    for _ in range(count):
        p = msg.pack(include_length_prefix=True)
        u = ISO8583Message.unpack(p, has_length_prefix=True, is_binary_bitmap=True)
        _ = u.build_response(ResponseCode.APPROVED).pack(include_length_prefix=True)
    t_cycle = time.perf_counter() - t0
    cycle_tps = count / t_cycle

    print(f"Wire Message Size:        {len(packed_bytes)} bytes")
    print(f"Pack Throughput:          {pack_tps:,.1f} msg/sec ({t_pack:.3f}s)")
    print(f"Unpack Throughput:        {unpack_tps:,.1f} msg/sec ({t_unpack:.3f}s)")
    print(f"Full Roundtrip Cycle:     {cycle_tps:,.1f} msg/sec ({t_cycle:.3f}s)")
    print("=" * 60)


def cmd_server(host: str = "127.0.0.1", port: int = 8583) -> None:
    """Run an interactive ISO 8583 TCP Mock Switch Server."""
    routing = RoutingTable()
    routing.add_route(RouteEntry("414345", "ECOBANK_GH", "127.0.0.1", 9001))
    routing.add_route(RouteEntry("539983", "STANBIC_GH", "127.0.0.1", 9002))
    routing.add_route(RouteEntry("504108", "GCB_BANK", "127.0.0.1", 9003))
    routing.default_route = RouteEntry("DEFAULT", "GHIPSS_NATIONAL_SWITCH", "127.0.0.1", 9000)

    engine = SwitchEngine(routing_table=routing)

    class ISOHandler(socketserver.BaseRequestHandler):
        def handle(self):
            print(f"[TCP] Client connected from {self.client_address}")
            while True:
                length_hdr = self.request.recv(2)
                if not length_hdr or len(length_hdr) < 2:
                    break
                (msg_len,) = struct.unpack(">H", length_hdr)
                payload = self.request.recv(msg_len)
                if not payload:
                    break

                full_wire = length_hdr + payload
                try:
                    inbound_msg = ISO8583Message.unpack(full_wire, has_length_prefix=True, is_binary_bitmap=True)
                    print(f"[SWITCH] Received MTI {inbound_msg.mti} | STAN: {inbound_msg.get(11)} | PAN: {inbound_msg.get(2)}")
                    response_msg = engine.process_inbound(inbound_msg)
                    resp_bytes = response_msg.pack(include_length_prefix=True)
                    self.request.sendall(resp_bytes)
                    print(f"[SWITCH] Replied MTI {response_msg.mti} | RC: {response_msg.get(39)}")
                except Exception as e:
                    print(f"[ERROR] Failed processing frame: {e}")
                    break

    print(f"Starting SwitchRail-8583 Server on {host}:{port} (Press Ctrl+C to stop)...")
    with socketserver.ThreadingTCPServer((host, port), ISOHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down switch server.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="switchrail", description="SwitchRail-8583 CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Inspect
    inspect_p = subparsers.add_parser("inspect", help="Inspect and dump raw ISO 8583 hex bytes")
    inspect_p.add_argument("--hex", required=True, help="Hex-encoded ISO 8583 message string")

    # Bench
    bench_p = subparsers.add_parser("bench", help="Run packing/unpacking micro-benchmarks")
    bench_p.add_argument("-n", "--count", type=int, default=30000, help="Number of messages")

    # TCP Socket Server
    server_p = subparsers.add_parser("server", help="Launch TCP mock ISO 8583 switch daemon")
    server_p.add_argument("--host", default="127.0.0.1", help="Bind IP")
    server_p.add_argument("--port", type=int, default=8583, help="Bind Port")

    # REST Gateway Server
    serve_p = subparsers.add_parser("serve", help="Launch FastAPI ISO 8583 REST Gateway service")
    serve_p.add_argument("--host", default="0.0.0.0", help="Binding host address")
    serve_p.add_argument("--port", type=int, default=8584, help="Binding port (default: 8584)")

    args = parser.parse_args()
    if args.command == "serve":
        from switchrail.server import serve
        serve(host=args.host, port=args.port)
    elif args.command == "inspect":
        cmd_unpack_hex(args.hex)
    elif args.command == "bench":
        cmd_bench(args.count)
    elif args.command == "server":
        cmd_server(args.host, args.port)


if __name__ == "__main__":
    main()

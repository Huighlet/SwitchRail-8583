"""
Unit tests for the Longest Prefix Match (LPM) BIN routing engine.
"""

import pytest

from switchrail.routing import RouteEntry, RoutingTable
from switchrail.types import RoutingError


def test_longest_prefix_match_routing():
    """Verify routing matches the most specific BIN prefix."""
    table = RoutingTable()
    route_visa = RouteEntry("4", "VISA_GLOBAL", "127.0.0.1", 9001)
    route_ecobank = RouteEntry("414345", "ECOBANK_GH", "127.0.0.1", 9002)
    route_stanbic = RouteEntry("539983", "STANBIC_GH", "127.0.0.1", 9003)

    table.add_route(route_visa)
    table.add_route(route_ecobank)
    table.add_route(route_stanbic)

    # 414345 matches Ecobank specifically, not the generic '4'
    match1 = table.match("4143459988776655")
    assert match1.destination_id == "ECOBANK_GH"

    # 499999 matches general Visa '4'
    match2 = table.match("4999991122334455")
    assert match2.destination_id == "VISA_GLOBAL"

    # Stanbic
    match3 = table.match("5399830000001234")
    assert match3.destination_id == "STANBIC_GH"


def test_default_route_fallback():
    """Verify unmapped cards fall back to default inter-bank clearing route."""
    default_route = RouteEntry("DEFAULT", "GHIPSS_CLEARING", "127.0.0.1", 9999)
    table = RoutingTable(default_route=default_route)

    match = table.match("6011000000001234")
    assert match.destination_id == "GHIPSS_CLEARING"


def test_unmatched_route_raises_routing_error():
    """Verify that unmatched PAN without default route raises RoutingError."""
    table = RoutingTable(default_route=None)
    with pytest.raises(RoutingError):
        table.match("6011000000001234")

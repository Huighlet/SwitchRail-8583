"""
SwitchRail-8583 Routing Engine.
Longest Prefix Match (LPM) BIN-based routing for inter-bank card rails and mobile money switches.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

from switchrail.types import RoutingError


@dataclasses.dataclass(slots=True, frozen=True)
class RouteEntry:
    """Destination target for a matched transaction route."""
    bin_prefix: str
    destination_id: str
    host: str
    port: int
    timeout_ms: int = 5000
    is_active: bool = True


class RoutingTable:
    """
    Dynamic Longest Prefix Match (LPM) Routing Table.
    Matches PAN (DE 2) against registered financial institution BIN ranges.
    """
    def __init__(self, default_route: Optional[RouteEntry] = None) -> None:
        self._routes: Dict[str, RouteEntry] = {}
        self.default_route = default_route

    def add_route(self, route: RouteEntry) -> None:
        """Register a destination route for a specific BIN prefix."""
        self._routes[route.bin_prefix] = route

    def remove_route(self, bin_prefix: str) -> None:
        """Remove a route."""
        self._routes.pop(bin_prefix, None)

    def match(self, pan: str) -> RouteEntry:
        """
        Locate optimal route using Longest Prefix Match (LPM) on card PAN.
        Checks prefixes from length 8 down to 1.
        """
        clean_pan = pan.strip()
        max_prefix_len = min(len(clean_pan), 8)

        # Iterate descending from longest prefix to shortest
        for prefix_len in range(max_prefix_len, 0, -1):
            sub = clean_pan[:prefix_len]
            if sub in self._routes:
                route = self._routes[sub]
                if route.is_active:
                    return route

        if self.default_route and self.default_route.is_active:
            return self.default_route

        raise RoutingError(f"No active route matches PAN prefix '{clean_pan[:6]}' and no default route is configured.")

    def all_routes(self) -> List[RouteEntry]:
        return list(self._routes.values())

"""
5-tuple flow identity and aggregation.

FlowKey canonicalizes the 5-tuple:

    proto, src_ip, src_port, dst_ip, dst_port

with IPv4-mapped IPv6 addresses normalized to plain IPv4 and IPv6
addresses lowercased.

FlowFilter is a lightweight matcher that supports wildcards. It is
also templatable into a bpftrace guard clause (see
linuxnetlens.backends.bpftrace) so we can push the filter into the
kernel and avoid per-packet user-space overhead.

FlowTable aggregates events by FlowKey with LRU eviction so that a
long capture cannot exhaust memory.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

_ALLOWED_PROTOS = frozenset({"tcp", "udp", "icmp", "icmpv6"})


def _canon_ip(addr: str) -> str:
    """
    Canonicalize an IPv4 or IPv6 string.

    IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) collapse to the
    embedded IPv4 form so a flow observed on one side as v4-mapped
    matches the same flow observed on the other side as plain v4.
    """

    if not addr:
        return ""

    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return addr.strip().lower()

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)

    return str(parsed)


def _canon_proto(proto: str) -> str:
    if not proto:
        return ""
    normalized = proto.strip().lower()
    return normalized


@dataclass(frozen=True)
class FlowKey:
    """
    Immutable, hashable 5-tuple.

    Ports are integers. ICMP flows use port 0 on both sides; the
    caller can attach the ICMP type/code via event metadata.
    """

    proto: str

    src_ip: str

    src_port: int

    dst_ip: str

    dst_port: int

    # ------------------------------------------------------------------
    # Construction / validation
    # ------------------------------------------------------------------

    @classmethod
    def make(
        cls,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> "FlowKey":
        """Canonicalizing constructor."""

        return cls(
            proto=_canon_proto(proto),
            src_ip=_canon_ip(src_ip),
            src_port=int(src_port or 0),
            dst_ip=_canon_ip(dst_ip),
            dst_port=int(dst_port or 0),
        )

    def reversed(self) -> "FlowKey":
        """Return the reverse-direction flow key (server↔client)."""

        return FlowKey(
            proto=self.proto,
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            dst_ip=self.src_ip,
            dst_port=self.src_port,
        )

    def is_valid(self) -> bool:
        return bool(self.proto in _ALLOWED_PROTOS and self.src_ip and self.dst_ip)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proto": self.proto,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowKey":
        return cls.make(
            proto=data.get("proto", ""),
            src_ip=data.get("src_ip", ""),
            src_port=data.get("src_port", 0),
            dst_ip=data.get("dst_ip", ""),
            dst_port=data.get("dst_port", 0),
        )

    def __str__(self) -> str:
        return f"{self.proto} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


# ----------------------------------------------------------------------
# FlowFilter: matcher with wildcards + bpftrace-templatable
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class FlowFilter:
    """
    Match a subset of flows.

    Any component may be None to mean "wildcard". The filter matches
    a FlowKey if every non-None component matches.

    A FlowFilter can also be matched against the *reverse* direction
    of a FlowKey to support server-side capture where the observed
    packet header order is swapped from what the user requested.
    """

    proto: Optional[str] = None

    src_ip: Optional[str] = None

    src_port: Optional[int] = None

    dst_ip: Optional[str] = None

    dst_port: Optional[int] = None

    bidirectional: bool = True

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @classmethod
    def parse(cls, spec: str) -> "FlowFilter":
        """
        Parse a compact filter spec.

        Grammar (informal)::

            <proto>:<src_ip>:<src_port>-><dst_ip>:<dst_port>

        ``*`` is the wildcard for any component. Examples::

            tcp:10.0.0.4:*->10.0.0.9:22
            tcp:*:*->10.0.0.9:443
            udp:*->10.0.0.9:53
            *:*->10.0.0.9:*

        Empty or "any" spec returns a fully-wildcarded filter.
        """

        if not spec or spec.strip().lower() == "any":
            return cls()

        text = spec.strip()

        if "->" not in text:
            raise ValueError(
                f"FlowFilter spec must contain '->': {spec!r}"
            )

        left, right = text.split("->", 1)
        left_parts = left.split(":")
        right_parts = right.split(":")

        # left = <proto>:<src_ip>[:<src_port>]
        # right = <dst_ip>:<dst_port>
        if len(left_parts) == 3:
            proto_s, src_ip_s, src_port_s = left_parts
        elif len(left_parts) == 2:
            proto_s, src_ip_s = left_parts
            src_port_s = "*"
        else:
            raise ValueError(f"FlowFilter: bad left side: {left!r}")

        if len(right_parts) == 2:
            dst_ip_s, dst_port_s = right_parts
        elif len(right_parts) == 1:
            dst_ip_s = right_parts[0]
            dst_port_s = "*"
        else:
            raise ValueError(f"FlowFilter: bad right side: {right!r}")

        def _opt_str(s: str) -> Optional[str]:
            s = s.strip()
            if not s or s == "*":
                return None
            return s.lower() if s.lower() in _ALLOWED_PROTOS else _canon_ip(s)

        def _opt_port(s: str) -> Optional[int]:
            s = s.strip()
            if not s or s == "*":
                return None
            return int(s)

        proto = proto_s.strip().lower()
        if proto == "*":
            proto = None
        elif proto not in _ALLOWED_PROTOS:
            raise ValueError(f"FlowFilter: unknown proto {proto!r}")

        return cls(
            proto=proto,
            src_ip=_opt_str(src_ip_s),
            src_port=_opt_port(src_port_s),
            dst_ip=_opt_str(dst_ip_s),
            dst_port=_opt_port(dst_port_s),
        )

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def matches(self, flow: Optional[FlowKey]) -> bool:
        """Return True if `flow` (or its reverse) matches."""

        if flow is None:
            # No flow attributed → we do not filter it in or out
            # here; higher layers decide (broad mode allows, scoped
            # mode filters).
            return True

        if self._match_one_direction(flow):
            return True

        if self.bidirectional and self._match_one_direction(flow.reversed()):
            return True

        return False

    def _match_one_direction(self, flow: FlowKey) -> bool:
        if self.proto is not None and flow.proto != self.proto:
            return False
        if self.src_ip is not None and flow.src_ip != self.src_ip:
            return False
        if self.src_port is not None and flow.src_port != self.src_port:
            return False
        if self.dst_ip is not None and flow.dst_ip != self.dst_ip:
            return False
        if self.dst_port is not None and flow.dst_port != self.dst_port:
            return False
        return True

    def is_broad(self) -> bool:
        """True if every component is wildcarded (matches everything)."""

        return not any([
            self.proto,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        ])

    # ------------------------------------------------------------------
    # bpftrace fragment
    # ------------------------------------------------------------------

    def as_bpftrace_guard(self, *, want_proto: bool = True) -> str:
        """
        Emit a bpftrace boolean expression for the filter.

        This is *not* used by SimulatedBackend; the BpftraceBackend
        splices it into its scripts so the kernel filters events
        before they hit the ring buffer.

        IP addresses are compared as little-endian u32 values against the
        raw ``$saddr_be`` / ``$daddr_be`` variables the .bt program sets
        from ``$iph->saddr`` / ``$iph->daddr`` (which are ``__be32`` in
        the kernel and appear as network-order bytes reinterpreted as
        LE u32 on x86_64). This avoids a bpftrace type-mismatch when
        comparing the ``inet`` result of ``ntop()`` to a string literal
        on bpftrace 0.17 (RHEL 8.10).

        Returns the string ``"1"`` if the filter is fully broad.
        """

        clauses: List[str] = []

        if want_proto and self.proto:
            proto_num = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}.get(
                self.proto
            )
            if proto_num is not None:
                clauses.append(f"$proto == {proto_num}")

        if self.src_ip:
            clauses.append(
                f"$saddr_be == {self._ipv4_to_le_u32(self.src_ip)}"
            )

        if self.src_port is not None:
            clauses.append(f"$sport == {self.src_port}")

        if self.dst_ip:
            clauses.append(
                f"$daddr_be == {self._ipv4_to_le_u32(self.dst_ip)}"
            )

        if self.dst_port is not None:
            clauses.append(f"$dport == {self.dst_port}")

        return " && ".join(clauses) if clauses else "1"

    @staticmethod
    def _ipv4_to_le_u32(ip: str) -> int:
        """
        Encode an IPv4 dotted-quad as the little-endian u32 that appears
        when ``__be32`` bytes are read as u32 on a little-endian host.
        Example: ``192.0.2.1`` (network bytes ``C0 00 02 01``) →
        ``0x010200C0`` = ``16908480``.
        """
        import socket

        return int.from_bytes(socket.inet_aton(ip), "little")


# ----------------------------------------------------------------------
# FlowTable: LRU-bounded aggregation
# ----------------------------------------------------------------------


@dataclass
class FlowRecord:
    """
    Per-flow aggregated record.

    Populated by ``FlowTable.add`` and consumed by the VerdictLedger,
    OutcomeClassifier, and RootCauseAttributor.
    """

    flow: FlowKey

    events: List[Any] = field(default_factory=list)

    first_seen: float = 0.0

    last_seen: float = 0.0

    event_count: int = 0

    def append(self, event: Any, timestamp: float) -> None:
        if self.first_seen == 0.0:
            self.first_seen = timestamp
        self.last_seen = timestamp
        self.events.append(event)
        self.event_count += 1


class FlowTable:
    """
    LRU-bounded aggregation by FlowKey with optional filter scoping.

    - ``max_flows``: hard cap on distinct flows kept in memory.
    - ``flow_filter``: only flows matching the filter are stored.
      Events with no attached flow (e.g., a PID mapping event with
      only a socket pointer) are always stored under the sentinel
      key so the SocketRegistry can still see them.
    """

    def __init__(
        self,
        max_flows: int = 10_000,
        flow_filter: Optional[FlowFilter] = None,
    ):
        self._flows: "OrderedDict[FlowKey, FlowRecord]" = OrderedDict()
        self._unattributed: List[Any] = []
        self._max_flows = max_flows
        self._filter = flow_filter
        self._evictions = 0

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    def add(self, event: Any) -> None:
        """
        Store an event in its flow bucket.

        Events without a ``flow`` attribute go into the
        ``unattributed`` bucket. Events whose flow does not match the
        active filter are silently dropped.
        """

        flow = getattr(event, "flow", None)

        if flow is None:
            self._unattributed.append(event)
            return

        if self._filter is not None and not self._filter.matches(flow):
            return

        timestamp = float(getattr(event, "timestamp", 0.0))

        record = self._flows.get(flow)

        if record is None:

            if len(self._flows) >= self._max_flows:
                # Evict oldest entry.
                self._flows.popitem(last=False)
                self._evictions += 1

            record = FlowRecord(flow=flow)
            self._flows[flow] = record
        else:
            # Refresh LRU order.
            self._flows.move_to_end(flow)

        record.append(event, timestamp)

    def extend(self, events: Iterable[Any]) -> None:
        for event in events:
            self.add(event)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def flows(self) -> List[FlowKey]:
        return list(self._flows.keys())

    def record(self, flow: FlowKey) -> Optional[FlowRecord]:
        return self._flows.get(flow)

    def unattributed(self) -> List[Any]:
        return list(self._unattributed)

    def evictions(self) -> int:
        return self._evictions

    def __len__(self) -> int:
        return len(self._flows)

    def __iter__(self) -> Iterator[Tuple[FlowKey, FlowRecord]]:
        return iter(self._flows.items())

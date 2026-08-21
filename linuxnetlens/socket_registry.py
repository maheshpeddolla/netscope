"""
SocketRegistry: PID / process / socket / netns correlation.

Requirement addressed: **do not rely only on socket allocation for
PID-to-flow correlation**.

The registry accepts events from up to four sources (in decreasing
fidelity):

    1. LSM hooks (lsm/socket_bind, lsm/socket_connect,
       lsm/socket_sendmsg) — RHEL 9 preferred.
    2. kprobes at process-context call sites
       (tcp_v4_connect, tcp_v6_connect, inet_csk_accept, inet_bind).
       These are ProcessEvent instances in LinuxNetLens's event
       model.
    3. TCP state events (sock:inet_sock_set_state) that carry the
       full 5-tuple. Combined with a prior sk->pid mapping, they
       stamp subsequent packet events with a PID at INFERRED
       certainty.
    4. Post-hoc user-space reconciliation from `ss -tanpH` /
       `ss -uanpH` output. Reports ASSUMED certainty.

Every emitted PID annotation carries its Certainty so downstream
code can apply the appropriate confidence multiplier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from linuxnetlens.events import (
    Certainty,
    Event,
    NfVerdictEvent,
    ProcessEvent,
    TcpResetEvent,
    TcpRetransmitEvent,
    TcpStateEvent,
)
from linuxnetlens.flow import FlowKey


@dataclass
class SocketOwner:
    """Attribution attached to a flow."""

    pid: Optional[int]

    comm: Optional[str]

    netns_ino: Optional[int]

    certainty: Certainty


class SocketRegistry:
    """
    Correlate flows with (pid, process name, netns) using multiple
    evidence sources.

    Usage::

        reg = SocketRegistry()
        reg.ingest(events)          # from a backend capture
        reg.reconcile_from_ss(text) # optional user-space snapshot
        owner = reg.owner(flow)
    """

    def __init__(self) -> None:
        # Flow -> best known owner. Higher-certainty wins.
        self._by_flow: Dict[FlowKey, SocketOwner] = {}

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, events: Iterable[Event]) -> None:

        for event in events:

            flow = getattr(event, "flow", None)

            if flow is None:
                continue

            if isinstance(event, ProcessEvent):
                # Process-context call site: highest fidelity.
                self._record(
                    flow=flow,
                    pid=event.pid,
                    comm=event.comm,
                    netns_ino=event.netns_ino,
                    certainty=Certainty.OBSERVED,
                )
                continue

            if isinstance(event, TcpStateEvent):
                # inet_sock_set_state may or may not carry a PID.
                # If it does (process context, e.g., during connect),
                # accept it as OBSERVED; if it doesn't, we still
                # record whatever the backend attached.
                self._record(
                    flow=flow,
                    pid=event.pid,
                    comm=event.comm,
                    netns_ino=event.netns_ino,
                    certainty=(
                        Certainty.OBSERVED
                        if event.certainty is Certainty.OBSERVED
                        and event.pid
                        else Certainty.INFERRED
                    ),
                )
                continue

            if isinstance(
                event,
                (TcpRetransmitEvent, TcpResetEvent, NfVerdictEvent),
            ):
                # These fire in softirq context most of the time.
                # Their PID annotations are only trustworthy at
                # INFERRED at best.
                if event.pid or event.comm:
                    self._record(
                        flow=flow,
                        pid=event.pid,
                        comm=event.comm,
                        netns_ino=event.netns_ino,
                        certainty=Certainty.INFERRED,
                    )
                continue

    # ------------------------------------------------------------------
    # User-space reconciliation
    # ------------------------------------------------------------------

    _SS_RE = re.compile(
        r"^(?P<proto>\S+)?\s*"
        r"(?P<state>\S+)\s+"
        r"\S+\s+\S+\s+"
        r"(?P<laddr>\S+)\s+"
        r"(?P<raddr>\S+)"
        r".*?users:\(\(\"(?P<comm>[^\"]+)\",pid=(?P<pid>\d+),"
    )

    def reconcile_from_ss(
        self,
        ss_output: str,
        proto: str = "tcp",
    ) -> None:
        """
        Ingest ``ss -tanpH`` / ``ss -uanpH`` output as ASSUMED
        certainty. Skipped if the format is unexpected.
        """

        if not ss_output:
            return

        for line in ss_output.splitlines():

            match = self._SS_RE.search(line)

            if match is None:
                continue

            laddr = match.group("laddr")
            raddr = match.group("raddr")
            comm = match.group("comm")
            pid = int(match.group("pid"))

            try:
                src_ip, src_port_str = laddr.rsplit(":", 1)
                dst_ip, dst_port_str = raddr.rsplit(":", 1)
                src_port = int(src_port_str)
                dst_port = int(dst_port_str)
            except ValueError:
                continue

            src_ip = src_ip.strip("[]")
            dst_ip = dst_ip.strip("[]")

            flow = FlowKey.make(
                proto=proto,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

            self._record(
                flow=flow,
                pid=pid,
                comm=comm,
                netns_ino=None,
                certainty=Certainty.ASSUMED,
            )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def owner(self, flow: FlowKey) -> Optional[SocketOwner]:
        """
        Look up the owner of a flow.

        We look up the direct flow first, then the reverse (many
        events on a server-side socket present the flow in the
        opposite direction).
        """

        owner = self._by_flow.get(flow)

        if owner is not None:
            return owner

        return self._by_flow.get(flow.reversed())

    def all_owners(self) -> List[Tuple[FlowKey, SocketOwner]]:
        return list(self._by_flow.items())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    _RANK = {
        Certainty.OBSERVED: 3,
        Certainty.INFERRED: 2,
        Certainty.ASSUMED: 1,
    }

    def _record(
        self,
        flow: FlowKey,
        pid: Optional[int],
        comm: Optional[str],
        netns_ino: Optional[int],
        certainty: Certainty,
    ) -> None:

        if pid is None and comm is None and netns_ino is None:
            return

        candidate = SocketOwner(
            pid=pid,
            comm=comm,
            netns_ino=netns_ino,
            certainty=certainty,
        )

        existing = self._by_flow.get(flow)

        if existing is None:
            self._by_flow[flow] = candidate
            return

        if self._RANK[candidate.certainty] > self._RANK[existing.certainty]:
            self._by_flow[flow] = candidate
            return

        # Merge missing fields at equal or lower certainty rather
        # than clobbering.
        merged = SocketOwner(
            pid=existing.pid if existing.pid is not None else candidate.pid,
            comm=existing.comm or candidate.comm,
            netns_ino=(
                existing.netns_ino
                if existing.netns_ino is not None
                else candidate.netns_ino
            ),
            certainty=existing.certainty,
        )

        self._by_flow[flow] = merged

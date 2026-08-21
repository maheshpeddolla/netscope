"""
VerdictLedger: per-flow ordered timeline of significant events.

Used by the OutcomeClassifier to decide BLOCKED / NO_RESPONSE /
RESET / UNKNOWN, and by the RootCauseAttributor to attach evidence
to the winning hypothesis.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from linuxnetlens.events import (
    Certainty,
    DropEvent,
    Event,
    EventKind,
    NfVerdict,
    NfVerdictEvent,
    ProcessEvent,
    ResetDirection,
    TcpResetEvent,
    TcpRetransmitEvent,
    TcpState,
    TcpStateEvent,
)
from linuxnetlens.flow import FlowKey
from linuxnetlens.kernel_map import BLOCKED_FAMILY_REASONS


@dataclass
class FlowTimeline:
    """
    Ordered per-flow event list plus a small cache of derived facts.

    The cached fields exist to keep OutcomeClassifier / attributor
    cheap when many flows are present. They are populated lazily.
    """

    flow: FlowKey

    events: List[Event] = field(default_factory=list)

    # Cached derived facts (populated on freeze()).
    frozen: bool = False

    saw_connect_syscall: bool = False

    reached_syn_sent: bool = False

    reached_established: bool = False

    retransmit_count: int = 0

    rto_fired: bool = False

    reset_directions: List[ResetDirection] = field(default_factory=list)

    nf_drop_verdicts: List[NfVerdictEvent] = field(default_factory=list)

    blocked_family_drops: List[DropEvent] = field(default_factory=list)

    other_drop_events: List[DropEvent] = field(default_factory=list)

    process_events: List[ProcessEvent] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Materialization
    # ------------------------------------------------------------------

    def freeze(self) -> "FlowTimeline":
        """Populate cached derived facts. Idempotent."""

        if self.frozen:
            return self

        for event in self.events:

            if isinstance(event, ProcessEvent):
                self.process_events.append(event)
                if "connect" in event.syscall:
                    self.saw_connect_syscall = True

            elif isinstance(event, TcpStateEvent):
                if event.new_state is TcpState.SYN_SENT:
                    self.reached_syn_sent = True
                elif event.new_state is TcpState.ESTABLISHED:
                    self.reached_established = True

            elif isinstance(event, TcpRetransmitEvent):
                self.retransmit_count += event.segment_count
                if event.rto_fired:
                    self.rto_fired = True

            elif isinstance(event, TcpResetEvent):
                self.reset_directions.append(event.direction)

            elif isinstance(event, NfVerdictEvent):
                if event.verdict in (NfVerdict.DROP, NfVerdict.REJECT):
                    self.nf_drop_verdicts.append(event)

            elif isinstance(event, DropEvent):
                if event.drop_reason in BLOCKED_FAMILY_REASONS:
                    self.blocked_family_drops.append(event)
                else:
                    self.other_drop_events.append(event)

        self.frozen = True

        return self


class VerdictLedger:
    """
    Build ``FlowTimeline`` objects from a stream of typed events.

    The ledger only appends; the OutcomeClassifier and the attributor
    both consume the resulting timelines read-only.
    """

    def __init__(self) -> None:
        self._timelines: Dict[FlowKey, FlowTimeline] = {}
        self._unattributed: List[Event] = []
        self._ordered_flows: List[FlowKey] = []

    def add(self, event: Event) -> None:

        flow = getattr(event, "flow", None)

        if flow is None:
            self._unattributed.append(event)
            return

        timeline = self._timelines.get(flow)

        if timeline is None:
            timeline = FlowTimeline(flow=flow)
            self._timelines[flow] = timeline
            self._ordered_flows.append(flow)

        timeline.events.append(event)

    def extend(self, events: Iterable[Event]) -> None:
        for event in events:
            self.add(event)

    def flows(self) -> List[FlowKey]:
        return list(self._ordered_flows)

    def timeline(self, flow: FlowKey) -> Optional[FlowTimeline]:

        timeline = self._timelines.get(flow)

        if timeline is None:
            return None

        return timeline.freeze()

    def all_timelines(self) -> List[FlowTimeline]:

        return [
            self._timelines[flow].freeze()
            for flow in self._ordered_flows
        ]

    def unattributed(self) -> List[Event]:
        return list(self._unattributed)

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def event_kind_counts(self) -> Dict[EventKind, int]:

        counts: Dict[EventKind, int] = defaultdict(int)

        for timeline in self._timelines.values():
            for event in timeline.events:
                counts[event.kind] += 1

        for event in self._unattributed:
            counts[event.kind] += 1

        return dict(counts)

    def total_events(self) -> int:

        return sum(len(t.events) for t in self._timelines.values()) + len(
            self._unattributed
        )

    def observed_certainty_ratio(self) -> float:
        """
        Fraction of events with OBSERVED certainty.

        Used by the attributor as one input into overall confidence.
        """

        total = 0
        observed = 0

        for timeline in self._timelines.values():
            for event in timeline.events:
                total += 1
                if event.certainty is Certainty.OBSERVED:
                    observed += 1

        if total == 0:
            return 0.0

        return observed / total

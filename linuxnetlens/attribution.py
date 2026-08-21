"""
RootCauseAttributor: fuse a VerdictLedger + SocketRegistry into a
LinuxNetLens Diagnosis.

The attributor computes TWO independent confidence numbers per flow:

    - ``outcome_confidence`` : how sure we are of BLOCKED /
      NO_RESPONSE / RESET / UNKNOWN. Computed by the
      OutcomeClassifier.
    - ``attribution_confidence`` : how sure we are of the winning
      DropLocation. Computed here from evidence weights, certainty
      factors, and corroboration multipliers.

They are reported separately so it is possible to say
"the outcome is NO_RESPONSE (high confidence) but we cannot
attribute the drop location above LOW confidence".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from linuxnetlens.backends import detect_backend
from linuxnetlens.backends.base import BpfBackend
from linuxnetlens.events import (
    Certainty,
    DropEvent,
    Event,
    NfVerdict,
    NfVerdictEvent,
    ResetDirection,
    TcpResetEvent,
    TcpRetransmitEvent,
)
from linuxnetlens.flow import FlowFilter, FlowKey
from linuxnetlens.kernel_map import (
    BLOCKED_FAMILY_REASONS,
    attribute_drop_reason,
)
from linuxnetlens.models import Diagnosis, DropLocation, Hypothesis, Outcome
from linuxnetlens.outcome import OutcomeClassifier, OutcomeVerdict
from linuxnetlens.socket_registry import SocketOwner, SocketRegistry
from linuxnetlens.verdict_ledger import FlowTimeline, VerdictLedger


# ----------------------------------------------------------------------
# Recommendation catalogue.
# ----------------------------------------------------------------------

_RECOMMENDATIONS = {
    DropLocation.FIREWALL: [
        "Inspect the guest firewall ruleset (nft list ruleset -a / iptables-save)",
        "Correlate the observed hook and pf with the responsible ruleset section",
        "Check whether recent policy changes or CNI updates coincide with the drops",
    ],
    DropLocation.TCP: [
        "Inspect nstat -az for TcpRetransSegs, TcpExtTCPBacklogDrop, TcpExt*Csum*",
        "Check ss -tim for retransmits and RTT variance",
        "Investigate path loss with mtr / traceroute --mtu",
    ],
    DropLocation.APPLICATION: [
        "Check the target process is listening (ss -tlnp)",
        "Inspect socket receive buffer sizing (SO_RCVBUF)",
        "Correlate with application logs / GC pauses",
    ],
    DropLocation.SOFTNET: [
        "Correlate with /proc/net/softnet_stat dropped/time_squeeze",
        "Check per-CPU utilization on softnet CPUs (mpstat -P ALL)",
    ],
    DropLocation.NIC_DRIVER: [
        "Inspect ethtool -S for rx_errors, rx_dropped, rx_missed_errors",
        "Verify RX ring size (ethtool -g) and IRQ affinity",
    ],
    DropLocation.XDP: [
        "Enumerate attached XDP programs with bpftool net show",
        "Correlate with CNI (Cilium / Calico) telemetry if applicable",
    ],
    DropLocation.TC: [
        "Inspect tc -s qdisc show for drop counters",
        "Check shaping / policing configuration on the flow's ifindex",
    ],
    DropLocation.UNKNOWN: [
        "Widen the capture window or extend the flow filter",
        "Re-run with more probes enabled",
    ],
}


# ----------------------------------------------------------------------
# AttributionResult
# ----------------------------------------------------------------------


@dataclass
class AttributionResult:
    """
    A collection of per-flow diagnoses plus capture metadata.

    ``diagnoses`` is ordered: the strongest / most actionable first.
    """

    diagnoses: List[Diagnosis] = field(default_factory=list)

    backend: str = "unknown"

    total_events: int = 0

    matched_flows: int = 0

    flow_filter: Optional[str] = None

    warnings: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------
# RootCauseAttributor
# ----------------------------------------------------------------------


class RootCauseAttributor:
    """
    Turn a stream of typed events into an AttributionResult.

    The attributor is deterministic and stateless; it can be reused.
    """

    def __init__(self, classifier: Optional[OutcomeClassifier] = None):
        self._classifier = classifier or OutcomeClassifier()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def attribute(
        self,
        events: Iterable[Event],
        *,
        backend_name: str = "unknown",
        flow_filter: Optional[FlowFilter] = None,
    ) -> AttributionResult:

        event_list = list(events)

        ledger = VerdictLedger()
        ledger.extend(event_list)

        registry = SocketRegistry()
        registry.ingest(event_list)

        timelines = ledger.all_timelines()

        if flow_filter is not None and not flow_filter.is_broad():
            timelines = [
                t for t in timelines if flow_filter.matches(t.flow)
            ]

        result = AttributionResult(
            backend=backend_name,
            total_events=len(event_list),
            matched_flows=len(timelines),
            flow_filter=str(flow_filter) if flow_filter else None,
        )

        if not timelines:
            result.diagnoses.append(
                self._empty_capture_diagnosis(flow_filter)
            )
            return result

        for timeline in timelines:
            diagnosis = self._diagnose_flow(timeline, registry.owner(timeline.flow))
            result.diagnoses.append(diagnosis)

        # Sort: most severe outcome first, then highest confidence.
        result.diagnoses.sort(
            key=lambda d: (
                self._severity_rank(d.severity),
                -d.outcome_confidence,
                -d.attribution_confidence,
            )
        )

        return result

    # ------------------------------------------------------------------
    # Per-flow diagnosis
    # ------------------------------------------------------------------

    def _diagnose_flow(
        self,
        timeline: FlowTimeline,
        owner: Optional[SocketOwner],
    ) -> Diagnosis:

        outcome_verdict = self._classifier.classify(timeline)

        # -------- Attribution -------------------------------------------
        hypothesis = self._score_attribution(timeline, outcome_verdict)

        # -------- Metadata (evidence-rich, no overclaims) ---------------
        metadata: Dict[str, Any] = {
            "flow": timeline.flow.to_dict(),
            "event_count": len(timeline.events),
        }

        # Firewall-specific metadata: only what the kernel gave us.
        if timeline.nf_drop_verdicts:
            first_verdict = timeline.nf_drop_verdicts[0]
            fw_meta: Dict[str, Any] = {
                "backend": self._nf_backend(timeline.nf_drop_verdicts),
                "verdict": first_verdict.verdict.value,
            }
            if first_verdict.hook:
                fw_meta["hook"] = first_verdict.hook
            if first_verdict.pf:
                fw_meta["pf"] = first_verdict.pf
            # Only claim a chain if the kernel probe actually captured
            # it. Otherwise the field is absent.
            chain = next(
                (
                    v.chain_name
                    for v in timeline.nf_drop_verdicts
                    if v.chain_name
                ),
                "",
            )
            if chain:
                fw_meta["chain"] = chain
            metadata["firewall"] = fw_meta

        if timeline.reset_directions:
            metadata["reset"] = {
                "direction": timeline.reset_directions[0].value,
                "count": len(timeline.reset_directions),
            }

        if timeline.retransmit_count:
            metadata["retransmits"] = timeline.retransmit_count
            metadata["rto_fired"] = timeline.rto_fired

        if owner is not None:
            metadata["owner"] = {
                "pid": owner.pid,
                "comm": owner.comm,
                "netns_ino": owner.netns_ino,
                "certainty": owner.certainty.value,
            }

        # -------- Severity ---------------------------------------------
        severity = self._severity(outcome_verdict.outcome, hypothesis.score)

        # -------- Recommendations --------------------------------------
        for rec in _RECOMMENDATIONS.get(
            hypothesis.name_enum, _RECOMMENDATIONS[DropLocation.UNKNOWN]
        ):
            hypothesis.recommend(rec)

        return Diagnosis(
            title="LinuxNetLens Network Diagnosis",
            outcome=outcome_verdict.outcome,
            location=hypothesis.name_enum,
            outcome_confidence=outcome_verdict.confidence,
            attribution_confidence=self._to_confidence(hypothesis.score),
            severity=severity,
            flow_summary=str(timeline.flow),
            process=owner.comm if owner and owner.comm else "",
            pid=owner.pid if owner else None,
            evidence=list(outcome_verdict.reasons) + list(hypothesis.evidence),
            recommendations=list(hypothesis.recommendations),
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Attribution scoring
    # ------------------------------------------------------------------

    def _score_attribution(
        self,
        timeline: FlowTimeline,
        outcome_verdict: OutcomeVerdict,
    ) -> "_ScoredHypothesis":
        """
        Build the winning ``_ScoredHypothesis`` for the flow.

        Scoring is priority-ordered so we do not overclaim:

            1. BLOCKED outcome + netfilter verdict → FIREWALL wins.
            2. BLOCKED outcome + blocked-family SKB reason → FIREWALL.
            3. RESET + NO_SOCKET SKB reason → APPLICATION (no listener).
            4. Otherwise pick the DropLocation with the highest
               weighted score across DropEvent evidence.
            5. If no drop-reason evidence exists but transmission
               evidence does → TCP (path loss).
            6. Fall through → UNKNOWN.
        """

        # -------- (1) + (2) BLOCKED family --------------------------
        if outcome_verdict.outcome is Outcome.BLOCKED:
            return self._score_blocked(timeline)

        # -------- (3) RESET with NO_SOCKET ---------------------------
        if outcome_verdict.outcome is Outcome.RESET:
            hypothesis = self._score_reset(timeline)
            if hypothesis is not None:
                return hypothesis

        # -------- (4) Drop-reason-driven attribution -----------------
        best = self._score_by_drop_reasons(timeline)
        if best is not None:
            return best

        # -------- (5) NO_RESPONSE with transmission evidence ---------
        if outcome_verdict.outcome is Outcome.NO_RESPONSE:
            return self._score_no_response(timeline)

        # -------- (6) UNKNOWN ---------------------------------------
        h = _ScoredHypothesis(DropLocation.UNKNOWN)
        h.add(10, "no attribution-quality evidence in capture window")
        return h

    def _score_blocked(self, timeline: FlowTimeline) -> "_ScoredHypothesis":

        h = _ScoredHypothesis(DropLocation.FIREWALL)

        for verdict in timeline.nf_drop_verdicts:
            weight = 70 * self._certainty_factor(verdict.certainty)
            h.add(
                weight,
                self._nf_evidence(verdict),
            )

        for drop in timeline.blocked_family_drops:
            weight = 60 * self._certainty_factor(drop.certainty)
            h.add(
                weight,
                f"{drop.drop_reason} observed for flow "
                f"(probe {drop.probe or 'kfree_skb'})",
            )

        # Corroboration bonus.
        if timeline.nf_drop_verdicts and timeline.blocked_family_drops:
            h.score *= 1.4

        return h

    def _score_reset(
        self, timeline: FlowTimeline
    ) -> Optional["_ScoredHypothesis"]:

        # NO_SOCKET + RST usually means "no listener on port X".
        no_socket = [
            d
            for d in timeline.blocked_family_drops
            + timeline.other_drop_events
            if d.drop_reason == "SKB_DROP_REASON_NO_SOCKET"
        ]

        if no_socket:
            h = _ScoredHypothesis(DropLocation.APPLICATION)
            h.add(
                65 * self._certainty_factor(no_socket[0].certainty),
                "TCP RST paired with SKB_DROP_REASON_NO_SOCKET → "
                "no listener on destination port",
            )
            return h

        # Otherwise attribute to TCP with moderate confidence.
        h = _ScoredHypothesis(DropLocation.TCP)
        direction = timeline.reset_directions[0]
        h.add(
            45,
            f"TCP RST observed ({direction.value})",
        )
        return h

    def _score_by_drop_reasons(
        self, timeline: FlowTimeline
    ) -> Optional["_ScoredHypothesis"]:

        drop_events: List[DropEvent] = (
            timeline.blocked_family_drops + timeline.other_drop_events
        )

        if not drop_events:
            return None

        buckets: Dict[DropLocation, "_ScoredHypothesis"] = {}

        for drop in drop_events:

            location, weight = attribute_drop_reason(drop.drop_reason)

            # Phase 1 refuses to select XDP/TC as the winning location
            # unless the SKB reason is explicit (which it is, by
            # construction here — but we still cap the weight below
            # FIREWALL/TCP to avoid drowning them without more
            # corroboration).
            if location in (DropLocation.XDP, DropLocation.TC):
                weight = int(weight * 0.6)

            bucket = buckets.setdefault(location, _ScoredHypothesis(location))
            bucket.add(
                weight * self._certainty_factor(drop.certainty),
                f"{drop.drop_reason or 'unknown skb reason'} "
                f"(probe {drop.probe or 'kfree_skb'})",
            )

        return max(buckets.values(), key=lambda h: h.score)

    def _score_no_response(
        self, timeline: FlowTimeline
    ) -> "_ScoredHypothesis":

        # No verdict, no reset, no drop reasons — attribute to TCP
        # with a modest score. This is honest: we know the flow left
        # us, and something upstream (or downstream in the guest not
        # yet observed) stopped it.
        h = _ScoredHypothesis(DropLocation.TCP)

        if timeline.retransmit_count:
            h.add(
                25 + min(timeline.retransmit_count, 8) * 5,
                f"{timeline.retransmit_count} TCP retransmit(s) "
                f"observed with no reply",
            )
            if timeline.rto_fired:
                h.add(15, "RTO timer fired (kernel gave up on the segment)")

        if timeline.reached_syn_sent and not timeline.reached_established:
            h.add(
                20,
                "flow never left SYN_SENT — remote peer never SYN-ACKed",
            )

        if not h.evidence:
            h.add(
                15,
                "transmission observed but no reply within the window",
            )

        return h

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _certainty_factor(certainty: Certainty) -> float:
        return {
            Certainty.OBSERVED: 1.0,
            Certainty.INFERRED: 0.75,
            Certainty.ASSUMED: 0.5,
        }[certainty]

    @staticmethod
    def _nf_backend(verdicts: List[NfVerdictEvent]) -> str:

        nft = any(v.nft_walker_seen for v in verdicts)
        ipt = any(v.ipt_walker_seen for v in verdicts)

        if nft and ipt:
            return "netfilter (nftables + iptables both walked)"
        if nft:
            return "nftables"
        if ipt:
            return "iptables"
        return "netfilter (backend unknown)"

    @staticmethod
    def _nf_evidence(verdict: NfVerdictEvent) -> str:

        parts = [f"nf_hook_slow verdict={verdict.verdict.value}"]

        if verdict.hook:
            parts.append(f"hook={verdict.hook}")
        if verdict.pf:
            parts.append(f"pf={verdict.pf}")
        if verdict.chain_name:
            parts.append(f"chain={verdict.chain_name}")
        if verdict.nft_walker_seen:
            parts.append("nft_do_chain observed")
        if verdict.ipt_walker_seen:
            parts.append("ipt_do_table observed")

        return " ".join(parts)

    @staticmethod
    def _to_confidence(score: float) -> int:

        if score <= 0:
            return 0

        return min(100, int(round(score / 1.4)))

    @staticmethod
    def _severity(outcome: Outcome, score: float) -> str:

        if outcome is Outcome.BLOCKED:
            return "critical"
        if outcome is Outcome.RESET:
            return "warning"
        if outcome is Outcome.NO_RESPONSE:
            return "warning" if score >= 40 else "info"
        return "info"

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {
            "critical": 0,
            "warning": 1,
            "info": 2,
            "ok": 3,
        }.get(severity, 4)

    def _empty_capture_diagnosis(
        self, flow_filter: Optional[FlowFilter]
    ) -> Diagnosis:

        return Diagnosis(
            title="LinuxNetLens Network Diagnosis",
            outcome=Outcome.UNKNOWN,
            location=DropLocation.UNKNOWN,
            outcome_confidence=0,
            attribution_confidence=0,
            severity="info",
            flow_summary=str(flow_filter) if flow_filter else "",
            evidence=[
                "No matching events were captured during the observation window."
            ],
            recommendations=[
                "Increase --duration",
                "Broaden --flow filter or omit it",
                "Verify probes are attached (linuxnetlens info)",
            ],
        )


# ----------------------------------------------------------------------
# Internal: a Hypothesis with a DropLocation attached.
# ----------------------------------------------------------------------


class _ScoredHypothesis(Hypothesis):
    """Hypothesis specialized with a DropLocation."""

    def __init__(self, location: DropLocation):
        super().__init__(name=location.value)
        self.name_enum: DropLocation = location


# ----------------------------------------------------------------------
# Convenience one-shot entry point.
# ----------------------------------------------------------------------


def run_attribution(
    duration: float = 10.0,
    *,
    backend: Optional[BpfBackend] = None,
    preferred_backend: Optional[str] = None,
    replay_path: Optional[str] = None,
    flow_filter: Optional[FlowFilter] = None,
) -> AttributionResult:
    """
    Capture events with the best available backend, then attribute.

    Never raises on missing eBPF: a SimulatedBackend is returned.
    """

    if backend is None:
        backend = detect_backend(
            preferred=preferred_backend,
            replay_path=replay_path,
        )

    events = backend.capture(duration=duration, flow_filter=flow_filter)

    return RootCauseAttributor().attribute(
        events,
        backend_name=backend.describe(),
        flow_filter=flow_filter,
    )

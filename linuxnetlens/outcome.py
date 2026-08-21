"""
Four-outcome classifier for LinuxNetLens.

Outcomes:

    - BLOCKED       : the local Linux guest OS dropped this flow.
                       Requires **explicit** kernel evidence.
    - NO_RESPONSE   : the flow left the guest but never got the
                       expected response. Retransmits and timeouts
                       fall in this bucket because they are
                       observationally indistinguishable from a
                       slow reply that arrived after our window.
    - RESET         : a TCP RST was observed on the flow's socket.
    - UNKNOWN       : we lack sufficient evidence to say anything.

Critical invariants (test-enforced):

    - We NEVER return BLOCKED without one of:
        (a) an NfVerdictEvent with verdict in {DROP, REJECT}, or
        (b) a DropEvent whose ``drop_reason`` is in
            ``BLOCKED_FAMILY_REASONS``.
    - Missing ESTABLISHED alone does NOT imply BLOCKED.
    - xdp_exception events (recorded in metadata) do NOT trigger
      BLOCKED; only ``SKB_DROP_REASON_XDP`` on a kfree_skb would,
      and it is NOT in ``BLOCKED_FAMILY_REASONS`` — XDP causing a
      guest-side drop is Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from linuxnetlens.events import (
    Certainty,
    NfVerdict,
    ResetDirection,
)
from linuxnetlens.models import Outcome
from linuxnetlens.verdict_ledger import FlowTimeline


@dataclass
class OutcomeVerdict:
    """
    Per-flow outcome + supporting evidence pointers.

    ``confidence`` is 0..100 for this classification alone (not for
    the downstream DropLocation attribution).
    """

    outcome: Outcome

    confidence: int

    reasons: List[str] = field(default_factory=list)

    reset_direction: Optional[ResetDirection] = None


class OutcomeClassifier:
    """
    Stateless classifier consuming a frozen ``FlowTimeline``.

    Decision matrix (first match wins):

    1. BLOCKED  — netfilter verdict DROP/REJECT observed on the flow,
                   OR a blocked-family SKB drop reason observed.
    2. RESET    — tcp:tcp_send_reset or tcp:tcp_receive_reset
                   observed.
    3. NO_RESPONSE — transmission evidence exists (connect syscall,
                     any state past CLOSE, or retransmits), AND
                     neither of the above matched.
    4. UNKNOWN  — no transmission evidence.
    """

    def classify(self, timeline: FlowTimeline) -> OutcomeVerdict:

        timeline.freeze()

        # ------------------------------------------------------------------
        # 1) BLOCKED
        # ------------------------------------------------------------------

        nf_drops = timeline.nf_drop_verdicts
        family_drops = timeline.blocked_family_drops

        if nf_drops or family_drops:

            reasons: List[str] = []

            if nf_drops:
                verdicts = ", ".join(
                    sorted({v.verdict.value for v in nf_drops})
                )
                reasons.append(
                    f"netfilter verdict {verdicts} observed on flow "
                    f"({len(nf_drops)} events)"
                )

            if family_drops:
                names = ", ".join(
                    sorted({d.drop_reason for d in family_drops})
                )
                reasons.append(
                    f"blocked-family skb drop reason(s): {names} "
                    f"({sum(1 for _ in family_drops)} events)"
                )

            confidence = self._blocked_confidence(nf_drops, family_drops)

            return OutcomeVerdict(
                outcome=Outcome.BLOCKED,
                confidence=confidence,
                reasons=reasons,
            )

        # ------------------------------------------------------------------
        # 2) RESET
        # ------------------------------------------------------------------

        if timeline.reset_directions:

            direction = timeline.reset_directions[0]

            confidence = min(
                100, 60 + 10 * len(timeline.reset_directions)
            )

            return OutcomeVerdict(
                outcome=Outcome.RESET,
                confidence=confidence,
                reasons=[
                    f"TCP RST observed ({direction.value}) "
                    f"× {len(timeline.reset_directions)}"
                ],
                reset_direction=direction,
            )

        # ------------------------------------------------------------------
        # 3) NO_RESPONSE
        # ------------------------------------------------------------------

        transmitted = (
            timeline.saw_connect_syscall
            or timeline.reached_syn_sent
            or timeline.reached_established
            or timeline.retransmit_count > 0
        )

        if transmitted:

            reasons = []

            if timeline.saw_connect_syscall:
                reasons.append("connect() syscall observed")
            if timeline.reached_syn_sent:
                reasons.append("state transition to SYN_SENT observed")
            if timeline.retransmit_count:
                reasons.append(
                    f"{timeline.retransmit_count} retransmit(s) observed"
                    + (" (RTO fired)" if timeline.rto_fired else "")
                )
            if timeline.reached_established and not timeline.retransmit_count:
                # Established but presumably closed with no data reply.
                reasons.append(
                    "connection reached ESTABLISHED then closed without reply"
                )

            confidence = 60
            if timeline.retransmit_count >= 3:
                confidence += 15
            if timeline.rto_fired:
                confidence += 10
            confidence = min(confidence, 95)

            return OutcomeVerdict(
                outcome=Outcome.NO_RESPONSE,
                confidence=confidence,
                reasons=reasons,
            )

        # ------------------------------------------------------------------
        # 4) UNKNOWN
        # ------------------------------------------------------------------

        return OutcomeVerdict(
            outcome=Outcome.UNKNOWN,
            confidence=0,
            reasons=[
                "insufficient evidence: no verdict, reset, "
                "or transmission indicator observed for this flow"
            ],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _blocked_confidence(nf_drops, family_drops) -> int:
        """
        Confidence in the BLOCKED classification.

        Base is high (>= 85) because the underlying signals are
        ground truth; corroboration (both signals present) pushes
        it to 98.
        """

        base = 0

        if nf_drops:
            observed = sum(
                1 for v in nf_drops if v.certainty is Certainty.OBSERVED
            )
            base = max(base, 88 + min(observed, 5))

        if family_drops:
            observed = sum(
                1 for d in family_drops if d.certainty is Certainty.OBSERVED
            )
            base = max(base, 85 + min(observed, 5))

        # Both signal sources present → very high confidence.
        if nf_drops and family_drops:
            base = max(base, 98)

        return min(base, 100)

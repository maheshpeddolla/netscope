"""
Tests for linuxnetlens.outcome.OutcomeClassifier.

Contains the **critical negative test**: retransmits + no netfilter
verdict + no reset must NOT be classified as BLOCKED. This is the
key correctness constraint of the whole Phase 1 pipeline.
"""

from __future__ import annotations

from linuxnetlens.events import (
    DropEvent,
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
from linuxnetlens.models import Outcome
from linuxnetlens.outcome import OutcomeClassifier
from linuxnetlens.verdict_ledger import VerdictLedger


def _flow():
    return FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 443)


def _classify(events):
    ledger = VerdictLedger()
    ledger.extend(events)
    tl = ledger.all_timelines()[0]
    return OutcomeClassifier().classify(tl)


# ----------------------------------------------------------------------
# CRITICAL NEGATIVE TEST
# ----------------------------------------------------------------------


def test_retransmits_without_verdict_or_reset_are_NOT_BLOCKED():
    """
    A flow with SYN_SENT + N retransmits + eventual close, and no
    netfilter verdict and no TCP RST, must be NO_RESPONSE — not
    BLOCKED. This is the single most important correctness
    invariant of Phase 1 to avoid overclaiming.
    """
    verdict = _classify([
        ProcessEvent(timestamp=1.0, flow=_flow(), syscall="tcp_v4_connect"),
        TcpStateEvent(
            timestamp=1.1,
            flow=_flow(),
            old_state=TcpState.CLOSE,
            new_state=TcpState.SYN_SENT,
        ),
        TcpRetransmitEvent(timestamp=2.0, flow=_flow(), segment_count=1),
        TcpRetransmitEvent(timestamp=4.0, flow=_flow(), segment_count=1),
        TcpRetransmitEvent(
            timestamp=8.0, flow=_flow(), segment_count=1, rto_fired=True
        ),
        TcpStateEvent(
            timestamp=20.0,
            flow=_flow(),
            old_state=TcpState.SYN_SENT,
            new_state=TcpState.CLOSE,
        ),
    ])
    assert verdict.outcome is Outcome.NO_RESPONSE
    assert verdict.outcome is not Outcome.BLOCKED


# ----------------------------------------------------------------------
# Positive cases
# ----------------------------------------------------------------------


def test_nf_drop_verdict_yields_BLOCKED():
    verdict = _classify([
        ProcessEvent(timestamp=1.0, flow=_flow(), syscall="tcp_v4_connect"),
        NfVerdictEvent(
            timestamp=1.1,
            flow=_flow(),
            hook="LOCAL_OUT",
            verdict=NfVerdict.DROP,
            nft_walker_seen=True,
        ),
    ])
    assert verdict.outcome is Outcome.BLOCKED
    assert verdict.confidence >= 85


def test_blocked_family_skb_reason_yields_BLOCKED():
    verdict = _classify([
        DropEvent(
            timestamp=1.0,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_NETFILTER_DROP",
        ),
    ])
    assert verdict.outcome is Outcome.BLOCKED


def test_bpf_cgroup_egress_yields_BLOCKED():
    verdict = _classify([
        DropEvent(
            timestamp=1.0,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_BPF_CGROUP_EGRESS",
        ),
    ])
    assert verdict.outcome is Outcome.BLOCKED


def test_tcp_csum_drop_is_NOT_BLOCKED():
    """
    TCP_CSUM is a stack-level issue, not a policy block. Classifier
    must not treat it as BLOCKED.
    """
    verdict = _classify([
        ProcessEvent(timestamp=1.0, flow=_flow(), syscall="tcp_v4_connect"),
        DropEvent(
            timestamp=1.1,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_TCP_CSUM",
        ),
    ])
    assert verdict.outcome is not Outcome.BLOCKED


def test_tcp_receive_reset_yields_RESET():
    verdict = _classify([
        TcpStateEvent(
            timestamp=1.0,
            flow=_flow(),
            old_state=TcpState.CLOSE,
            new_state=TcpState.SYN_SENT,
        ),
        TcpResetEvent(
            timestamp=1.1,
            flow=_flow(),
            direction=ResetDirection.REMOTE,
        ),
    ])
    assert verdict.outcome is Outcome.RESET
    assert verdict.reset_direction is ResetDirection.REMOTE


def test_no_transmission_evidence_yields_UNKNOWN():
    ledger = VerdictLedger()
    ledger.add(
        # Non-connect process event (won't set saw_connect_syscall)
        ProcessEvent(
            timestamp=1.0,
            flow=_flow(),
            syscall="socket",
        )
    )
    verdict = OutcomeClassifier().classify(ledger.all_timelines()[0])
    assert verdict.outcome is Outcome.UNKNOWN


def test_reset_takes_precedence_over_transmission_only():
    """RESET wins over NO_RESPONSE even if retransmits are present."""
    verdict = _classify([
        TcpRetransmitEvent(timestamp=1.0, flow=_flow(), segment_count=1),
        TcpResetEvent(
            timestamp=1.1,
            flow=_flow(),
            direction=ResetDirection.LOCAL,
        ),
    ])
    assert verdict.outcome is Outcome.RESET


def test_blocked_takes_precedence_over_reset():
    """
    When both a netfilter DROP and a RESET are present, BLOCKED
    wins because policy-level evidence is stronger than a stray
    RST symptom.
    """
    verdict = _classify([
        NfVerdictEvent(
            timestamp=1.0,
            flow=_flow(),
            verdict=NfVerdict.DROP,
            hook="LOCAL_OUT",
        ),
        TcpResetEvent(
            timestamp=1.1,
            flow=_flow(),
            direction=ResetDirection.LOCAL,
        ),
    ])
    assert verdict.outcome is Outcome.BLOCKED

"""Tests for linuxnetlens.verdict_ledger."""

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
from linuxnetlens.verdict_ledger import VerdictLedger


def _flow():
    return FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 443)


def test_ledger_bins_events_by_flow():
    ledger = VerdictLedger()
    ledger.extend([
        ProcessEvent(timestamp=1.0, flow=_flow(), syscall="tcp_v4_connect"),
        TcpStateEvent(
            timestamp=2.0,
            flow=_flow(),
            old_state=TcpState.CLOSE,
            new_state=TcpState.SYN_SENT,
        ),
    ])
    timelines = ledger.all_timelines()
    assert len(timelines) == 1
    assert timelines[0].saw_connect_syscall
    assert timelines[0].reached_syn_sent


def test_ledger_counts_retransmits():
    ledger = VerdictLedger()
    ledger.extend([
        TcpRetransmitEvent(timestamp=1.0, flow=_flow(), segment_count=1),
        TcpRetransmitEvent(timestamp=2.0, flow=_flow(), segment_count=1),
        TcpRetransmitEvent(
            timestamp=3.0, flow=_flow(), segment_count=1, rto_fired=True
        ),
    ])
    tl = ledger.all_timelines()[0]
    assert tl.retransmit_count == 3
    assert tl.rto_fired


def test_ledger_detects_reset_direction():
    ledger = VerdictLedger()
    ledger.add(
        TcpResetEvent(
            timestamp=1.0,
            flow=_flow(),
            direction=ResetDirection.REMOTE,
        )
    )
    tl = ledger.all_timelines()[0]
    assert tl.reset_directions == [ResetDirection.REMOTE]


def test_ledger_partitions_blocked_family_drops():
    ledger = VerdictLedger()
    ledger.extend([
        DropEvent(
            timestamp=1.0,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_NETFILTER_DROP",
        ),
        DropEvent(
            timestamp=2.0,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_TCP_CSUM",
        ),
    ])
    tl = ledger.all_timelines()[0]
    assert len(tl.blocked_family_drops) == 1
    assert len(tl.other_drop_events) == 1


def test_ledger_captures_nf_drops():
    ledger = VerdictLedger()
    ledger.add(
        NfVerdictEvent(
            timestamp=1.0,
            flow=_flow(),
            verdict=NfVerdict.DROP,
            hook="LOCAL_OUT",
        )
    )
    tl = ledger.all_timelines()[0]
    assert len(tl.nf_drop_verdicts) == 1


def test_events_without_flow_go_to_unattributed():
    ledger = VerdictLedger()
    ledger.add(ProcessEvent(timestamp=1.0, flow=None, syscall="close"))
    assert ledger.all_timelines() == []
    assert len(ledger.unattributed()) == 1

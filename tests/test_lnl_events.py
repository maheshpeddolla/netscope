"""Tests for linuxnetlens.events serialization."""

from __future__ import annotations

import pytest

from linuxnetlens.events import (
    Certainty,
    DropEvent,
    EventKind,
    NfVerdict,
    NfVerdictEvent,
    ProcessEvent,
    ResetDirection,
    TcpResetEvent,
    TcpRetransmitEvent,
    TcpState,
    TcpStateEvent,
    event_from_dict,
    event_to_dict,
)
from linuxnetlens.flow import FlowKey


def _flow():
    return FlowKey.make("tcp", "10.0.0.1", 5000, "10.0.0.2", 443)


def test_drop_event_roundtrip():
    event = DropEvent(
        timestamp=1.0,
        flow=_flow(),
        drop_reason="SKB_DROP_REASON_NETFILTER_DROP",
        kernel_function="nf_hook_slow",
        certainty=Certainty.OBSERVED,
        probe="kfree_skb",
    )
    d = event_to_dict(event)
    assert d["kind"] == "skb_drop"
    assert d["drop_reason"] == "SKB_DROP_REASON_NETFILTER_DROP"

    restored = event_from_dict(d)
    assert isinstance(restored, DropEvent)
    assert restored.drop_reason == "SKB_DROP_REASON_NETFILTER_DROP"
    assert restored.flow == event.flow


def test_tcp_state_event_roundtrip():
    event = TcpStateEvent(
        timestamp=2.0,
        flow=_flow(),
        old_state=TcpState.CLOSE,
        new_state=TcpState.SYN_SENT,
    )
    restored = event_from_dict(event_to_dict(event))
    assert isinstance(restored, TcpStateEvent)
    assert restored.new_state is TcpState.SYN_SENT


def test_tcp_retransmit_and_reset_roundtrip():
    r = TcpRetransmitEvent(timestamp=3.0, flow=_flow(), segment_count=2, rto_fired=True)
    rst = TcpResetEvent(timestamp=4.0, flow=_flow(), direction=ResetDirection.REMOTE)

    r2 = event_from_dict(event_to_dict(r))
    rst2 = event_from_dict(event_to_dict(rst))

    assert isinstance(r2, TcpRetransmitEvent)
    assert r2.segment_count == 2 and r2.rto_fired

    assert isinstance(rst2, TcpResetEvent)
    assert rst2.direction is ResetDirection.REMOTE


def test_nf_verdict_never_leaks_rule_handle():
    """
    NfVerdictEvent's schema must not accept a 'rule_handle' field.
    Phase 1 refuses to claim rule identity.
    """
    event = NfVerdictEvent(
        timestamp=5.0,
        flow=_flow(),
        hook="LOCAL_OUT",
        pf="NFPROTO_IPV4",
        verdict=NfVerdict.DROP,
        nft_walker_seen=True,
        chain_name="OUTPUT",
    )
    d = event_to_dict(event)
    assert "rule_handle" not in d
    assert "rule_number" not in d
    assert d["chain_name"] == "OUTPUT"


def test_process_event_roundtrip():
    p = ProcessEvent(
        timestamp=6.0,
        flow=_flow(),
        pid=1234,
        comm="curl",
        syscall="tcp_v4_connect",
    )
    p2 = event_from_dict(event_to_dict(p))
    assert isinstance(p2, ProcessEvent)
    assert p2.pid == 1234
    assert p2.syscall == "tcp_v4_connect"


def test_unknown_kind_raises():
    with pytest.raises((ValueError, KeyError)):
        event_from_dict({"kind": "not_a_real_kind", "timestamp": 0.0})


def test_tcp_state_coerce_unknown():
    assert TcpState.coerce("BOGUS") is TcpState.UNKNOWN
    assert TcpState.coerce(None) is TcpState.UNKNOWN
    assert TcpState.coerce("ESTABLISHED") is TcpState.ESTABLISHED


def test_eventkind_values_are_stable():
    assert EventKind.SKB_DROP.value == "skb_drop"
    assert EventKind.NF_VERDICT.value == "nf_verdict"
    assert EventKind.TCP_RESET.value == "tcp_reset"

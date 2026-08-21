"""Tests for linuxnetlens.socket_registry."""

from __future__ import annotations

from linuxnetlens.events import (
    Certainty,
    NfVerdict,
    NfVerdictEvent,
    ProcessEvent,
    TcpRetransmitEvent,
    TcpState,
    TcpStateEvent,
)
from linuxnetlens.flow import FlowKey
from linuxnetlens.socket_registry import SocketRegistry


def _flow():
    return FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 443)


def test_process_event_gives_observed_owner():
    reg = SocketRegistry()
    reg.ingest([
        ProcessEvent(
            timestamp=1.0,
            flow=_flow(),
            pid=1234,
            comm="curl",
            syscall="tcp_v4_connect",
        )
    ])
    owner = reg.owner(_flow())
    assert owner is not None
    assert owner.pid == 1234
    assert owner.comm == "curl"
    assert owner.certainty is Certainty.OBSERVED


def test_reverse_flow_lookup():
    reg = SocketRegistry()
    reg.ingest([
        ProcessEvent(
            timestamp=1.0,
            flow=_flow(),
            pid=1234,
            comm="curl",
            syscall="tcp_v4_connect",
        )
    ])
    assert reg.owner(_flow().reversed()) is not None


def test_softirq_events_are_only_inferred():
    reg = SocketRegistry()
    reg.ingest([
        TcpRetransmitEvent(
            timestamp=1.0,
            flow=_flow(),
            pid=9,
            comm="ksoftirqd",
        )
    ])
    owner = reg.owner(_flow())
    assert owner is not None
    assert owner.certainty is Certainty.INFERRED


def test_observed_overrides_inferred():
    reg = SocketRegistry()
    reg.ingest([
        TcpRetransmitEvent(
            timestamp=1.0,
            flow=_flow(),
            pid=9,
            comm="ksoftirqd",
        ),
        ProcessEvent(
            timestamp=2.0,
            flow=_flow(),
            pid=1234,
            comm="curl",
            syscall="tcp_v4_connect",
        ),
    ])
    owner = reg.owner(_flow())
    assert owner is not None
    assert owner.pid == 1234
    assert owner.certainty is Certainty.OBSERVED


def test_ss_reconciliation_is_assumed():
    reg = SocketRegistry()
    ss_output = (
        "tcp   ESTAB      0      0  10.0.0.4:51000  10.0.0.9:443  "
        "users:((\"curl\",pid=4242,fd=3))\n"
    )
    reg.reconcile_from_ss(ss_output, proto="tcp")
    owner = reg.owner(_flow())
    assert owner is not None
    assert owner.certainty is Certainty.ASSUMED
    assert owner.pid == 4242
    assert owner.comm == "curl"


def test_nfverdict_softirq_pid_never_observed():
    """
    An NfVerdictEvent runs in softirq and its ``pid`` cannot be a
    trustworthy owner even if the event carries one.
    """
    reg = SocketRegistry()
    reg.ingest([
        NfVerdictEvent(
            timestamp=1.0,
            flow=_flow(),
            pid=1,
            comm="swapper/0",
            verdict=NfVerdict.DROP,
        )
    ])
    owner = reg.owner(_flow())
    assert owner is not None
    assert owner.certainty is not Certainty.OBSERVED

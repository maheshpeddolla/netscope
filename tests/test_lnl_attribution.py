"""Tests for linuxnetlens.attribution.RootCauseAttributor."""

from __future__ import annotations

from pathlib import Path

from linuxnetlens.attribution import RootCauseAttributor, run_attribution
from linuxnetlens.backends.simulated import SimulatedBackend
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
from linuxnetlens.flow import FlowFilter, FlowKey
from linuxnetlens.models import DropLocation, Outcome


FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "linuxnetlens"


def _flow():
    return FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 443)


# ----------------------------------------------------------------------
# Fixture-based end-to-end
# ----------------------------------------------------------------------


def test_blocked_nft_fixture_end_to_end():
    result = run_attribution(
        replay_path=str(FIXTURES / "blocked_nft.json"),
        flow_filter=None,
    )
    assert len(result.diagnoses) == 1
    d = result.diagnoses[0]
    assert d.outcome is Outcome.BLOCKED
    assert d.location is DropLocation.FIREWALL
    assert d.outcome_confidence >= 85
    assert d.pid == 4242
    assert d.process == "curl"
    fw = d.metadata.get("firewall") or {}
    # We received nft walker evidence + a chain name.
    assert "nftables" in fw.get("backend", "")
    assert fw.get("chain") == "OUTPUT"
    assert fw.get("hook") == "LOCAL_OUT"


def test_no_response_fixture_is_not_blocked():
    """Regression guard for the overclaim bug."""
    result = run_attribution(
        replay_path=str(FIXTURES / "no_response.json"),
    )
    assert len(result.diagnoses) == 1
    d = result.diagnoses[0]
    assert d.outcome is Outcome.NO_RESPONSE
    # Must never accidentally attribute FIREWALL without evidence.
    assert d.location is not DropLocation.FIREWALL
    # No firewall metadata should be present.
    assert "firewall" not in d.metadata


def test_reset_remote_fixture_returns_reset():
    result = run_attribution(
        replay_path=str(FIXTURES / "reset_remote.json"),
    )
    diagnoses = [d for d in result.diagnoses if d.outcome is Outcome.RESET]
    assert diagnoses, "expected at least one RESET diagnosis"


def test_empty_fixture_yields_unknown_diagnosis():
    result = run_attribution(
        replay_path=str(FIXTURES / "unknown_empty.json"),
    )
    assert len(result.diagnoses) == 1
    assert result.diagnoses[0].outcome is Outcome.UNKNOWN


# ----------------------------------------------------------------------
# Direct API cases
# ----------------------------------------------------------------------


def test_attributor_produces_dual_confidence_numbers():
    attributor = RootCauseAttributor()
    result = attributor.attribute([
        NfVerdictEvent(
            timestamp=1.0,
            flow=_flow(),
            hook="LOCAL_OUT",
            verdict=NfVerdict.DROP,
            nft_walker_seen=True,
        ),
        DropEvent(
            timestamp=1.1,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_NETFILTER_DROP",
        ),
    ])
    d = result.diagnoses[0]
    assert 0 <= d.outcome_confidence <= 100
    assert 0 <= d.attribution_confidence <= 100
    assert d.outcome is Outcome.BLOCKED
    assert d.location is DropLocation.FIREWALL


def test_flow_filter_restricts_diagnoses():
    other = FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 22)
    events = [
        NfVerdictEvent(
            timestamp=1.0,
            flow=_flow(),
            verdict=NfVerdict.DROP,
            hook="LOCAL_OUT",
        ),
        TcpResetEvent(
            timestamp=2.0,
            flow=other,
            direction=ResetDirection.REMOTE,
        ),
    ]
    result = RootCauseAttributor().attribute(
        events,
        flow_filter=FlowFilter.parse("tcp:*:*->10.0.0.9:443"),
    )
    assert len(result.diagnoses) == 1
    assert result.diagnoses[0].outcome is Outcome.BLOCKED


def test_xdp_reason_is_evidence_but_does_not_overclaim():
    """
    An SKB_DROP_REASON_XDP alone must not classify as BLOCKED.
    """
    events = [
        DropEvent(
            timestamp=1.0,
            flow=_flow(),
            drop_reason="SKB_DROP_REASON_XDP",
        ),
    ]
    result = RootCauseAttributor().attribute(events)
    d = result.diagnoses[0]
    assert d.outcome is not Outcome.BLOCKED


def test_no_response_attributes_to_tcp():
    events = [
        ProcessEvent(timestamp=1.0, flow=_flow(), syscall="tcp_v4_connect"),
        TcpStateEvent(
            timestamp=1.1,
            flow=_flow(),
            old_state=TcpState.CLOSE,
            new_state=TcpState.SYN_SENT,
        ),
        TcpRetransmitEvent(timestamp=2.0, flow=_flow(), segment_count=1),
        TcpRetransmitEvent(timestamp=4.0, flow=_flow(), segment_count=1),
    ]
    result = RootCauseAttributor().attribute(events)
    d = result.diagnoses[0]
    assert d.outcome is Outcome.NO_RESPONSE
    assert d.location is DropLocation.TCP


def test_simulated_backend_captures_from_iterable():
    events = [
        ProcessEvent(timestamp=1.0, flow=_flow(), syscall="tcp_v4_connect"),
    ]
    backend = SimulatedBackend(events=events)
    captured = backend.capture()
    assert len(captured) == 1

"""Tests for linuxnetlens.kernel_map."""

from __future__ import annotations

from linuxnetlens.kernel_map import (
    BLOCKED_FAMILY_REASONS,
    DROP_REASON_MAP,
    attribute_drop_reason,
)
from linuxnetlens.models import DropLocation


def test_blocked_family_only_holds_expected_reasons():
    """
    BLOCKED_FAMILY_REASONS is the *only* set the outcome classifier
    is allowed to treat as sufficient evidence of BLOCKED. It must
    NEVER include ambiguous reasons like NOT_SPECIFIED, XDP,
    QDISC_DROP, TCP_CSUM, NO_SOCKET.
    """
    forbidden = {
        "SKB_DROP_REASON_NOT_SPECIFIED",
        "SKB_DROP_REASON_XDP",
        "SKB_DROP_REASON_QDISC_DROP",
        "SKB_DROP_REASON_TCP_CSUM",
        "SKB_DROP_REASON_NO_SOCKET",
        "SKB_DROP_REASON_TCP_RESET",
    }
    assert BLOCKED_FAMILY_REASONS.isdisjoint(forbidden)
    assert "SKB_DROP_REASON_NETFILTER_DROP" in BLOCKED_FAMILY_REASONS


def test_attribute_known_reason():
    location, weight = attribute_drop_reason("SKB_DROP_REASON_NETFILTER_DROP")
    assert location is DropLocation.FIREWALL
    assert weight > 0


def test_attribute_unknown_reason_is_unknown_low_weight():
    location, weight = attribute_drop_reason("SKB_DROP_REASON_TOTALLY_MADE_UP")
    assert location is DropLocation.UNKNOWN
    assert weight <= 15


def test_no_socket_maps_to_application():
    location, _ = attribute_drop_reason("SKB_DROP_REASON_NO_SOCKET")
    assert location is DropLocation.APPLICATION


def test_cpu_backlog_maps_to_softnet():
    location, _ = attribute_drop_reason("SKB_DROP_REASON_CPU_BACKLOG")
    assert location is DropLocation.SOFTNET


def test_all_map_entries_reference_valid_droplocation():
    for reason, (loc, weight) in DROP_REASON_MAP.items():
        assert isinstance(loc, DropLocation)
        assert 0 < weight < 200
        assert reason.startswith("SKB_DROP_REASON_")

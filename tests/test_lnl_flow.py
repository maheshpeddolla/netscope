"""Tests for linuxnetlens.flow."""

from __future__ import annotations

import pytest

from linuxnetlens.flow import FlowFilter, FlowKey, FlowTable


def test_flowkey_canonicalizes_ipv4_mapped_ipv6():
    f1 = FlowKey.make("tcp", "::ffff:10.0.0.4", 5000, "10.0.0.9", 443)
    f2 = FlowKey.make("tcp", "10.0.0.4", 5000, "10.0.0.9", 443)
    assert f1 == f2


def test_flowkey_reversed():
    f = FlowKey.make("tcp", "10.0.0.4", 5000, "10.0.0.9", 443)
    r = f.reversed()
    assert r.src_ip == "10.0.0.9"
    assert r.dst_ip == "10.0.0.4"
    assert r.src_port == 443
    assert r.dst_port == 5000
    assert r.reversed() == f


def test_flowkey_dict_roundtrip():
    f = FlowKey.make("tcp", "10.0.0.4", 5000, "10.0.0.9", 443)
    assert FlowKey.from_dict(f.to_dict()) == f


def test_flowkey_str_format():
    f = FlowKey.make("tcp", "10.0.0.4", 5000, "10.0.0.9", 443)
    assert "tcp 10.0.0.4:5000 -> 10.0.0.9:443" == str(f)


def test_filter_parse_and_match():
    ff = FlowFilter.parse("tcp:10.0.0.4:*->10.0.0.9:443")
    good = FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 443)
    bad = FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 22)
    assert ff.matches(good)
    assert not ff.matches(bad)


def test_filter_bidirectional_match():
    ff = FlowFilter.parse("tcp:10.0.0.4:*->10.0.0.9:443")
    rev = FlowKey.make("tcp", "10.0.0.9", 443, "10.0.0.4", 51000)
    assert ff.matches(rev), "bidirectional matching should catch reversed flows"


def test_filter_any_is_broad():
    assert FlowFilter.parse("any").is_broad()
    assert FlowFilter().is_broad()
    assert not FlowFilter.parse("tcp:*:*->10.0.0.9:443").is_broad()


def test_filter_invalid_spec_raises():
    with pytest.raises(ValueError):
        FlowFilter.parse("garbage-no-arrow")


def test_filter_as_bpftrace_guard():
    ff = FlowFilter.parse("tcp:*:*->10.0.0.9:443")
    guard = ff.as_bpftrace_guard()
    # IPv4 is compared as little-endian u32 to match the .bt program's
    # $daddr_be variable ($iph->daddr read as u32 on x86_64).
    # 10.0.0.9 → network bytes 0a 00 00 09 → LE u32 0x0900000a
    from linuxnetlens.flow import FlowFilter as _FF
    expected = _FF._ipv4_to_le_u32("10.0.0.9")
    assert "$proto == 6" in guard
    assert f"$daddr_be == {expected}" in guard
    assert "$dport == 443" in guard


def test_filter_broad_guard_is_true_literal():
    assert FlowFilter().as_bpftrace_guard() == "1"


def test_flowtable_aggregates_and_evicts():
    table = FlowTable(max_flows=2)

    class E:
        def __init__(self, flow, ts):
            self.flow = flow
            self.timestamp = ts

    f1 = FlowKey.make("tcp", "1.1.1.1", 1000, "2.2.2.2", 80)
    f2 = FlowKey.make("tcp", "1.1.1.1", 1001, "2.2.2.2", 80)
    f3 = FlowKey.make("tcp", "1.1.1.1", 1002, "2.2.2.2", 80)

    table.add(E(f1, 1.0))
    table.add(E(f2, 2.0))
    table.add(E(f3, 3.0))

    assert len(table) == 2
    assert table.evictions() == 1


def test_flowtable_scoped_filter_drops_non_matching():
    table = FlowTable(flow_filter=FlowFilter.parse("tcp:*:*->10.0.0.9:443"))

    class E:
        def __init__(self, flow, ts):
            self.flow = flow
            self.timestamp = ts

    match = FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 443)
    other = FlowKey.make("tcp", "10.0.0.4", 51000, "10.0.0.9", 22)

    table.add(E(match, 1.0))
    table.add(E(other, 2.0))

    assert len(table) == 1

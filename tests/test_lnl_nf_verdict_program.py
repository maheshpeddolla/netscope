"""
Phase 1.5 smoke test for programs/nf_verdict.bt.

Cannot run bpftrace on Windows/CI, so this test only validates the .bt
source shape:

    - it exists
    - it wires up the kprobe/kretprobe pair on nf_hook_slow
    - it walks nft_do_chain and ipt_do_table for corroboration booleans
    - it extracts a real 5-tuple (ntop + struct iphdr/tcphdr) instead of
      emitting hardcoded 0.0.0.0 placeholders
    - it NEVER references a rule handle or fabricates a chain name

These are regression guards for the Phase 1 → Phase 1.5 transition.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


PROGRAM = (
    Path(__file__).resolve().parent.parent
    / "linuxnetlens" / "programs" / "nf_verdict.bt"
)


@pytest.fixture(scope="module")
def bt_source() -> str:
    return PROGRAM.read_text(encoding="utf-8")


def test_nf_verdict_program_exists():
    assert PROGRAM.exists(), f"missing bpftrace program: {PROGRAM}"


def test_attaches_to_nf_hook_slow_kprobe_pair(bt_source: str):
    assert "kprobe:nf_hook_slow" in bt_source
    assert "kretprobe:nf_hook_slow" in bt_source


def test_captures_walker_booleans(bt_source: str):
    assert "kprobe:nft_do_chain" in bt_source
    assert "kprobe:ipt_do_table" in bt_source
    assert "nft_walker_seen" in bt_source
    assert "ipt_walker_seen" in bt_source


def test_extracts_real_5_tuple_not_hardcoded(bt_source: str):
    # Real extraction uses ntop() and iphdr / tcphdr struct access.
    assert "ntop(" in bt_source
    assert "struct iphdr" in bt_source
    assert "struct tcphdr" in bt_source
    assert "$iph->saddr" in bt_source
    assert "$iph->daddr" in bt_source
    assert "$tcph->source" in bt_source
    assert "$tcph->dest" in bt_source

    # Regression: the previous skeleton emitted a hardcoded literal.
    # Real path must not embed `"src_ip":"0.0.0.0"` as a literal.
    hardcoded = re.search(
        r'"src_ip"\s*:\s*"0\.0\.0\.0"', bt_source
    )
    assert hardcoded is None, (
        "nf_verdict.bt still emits a hardcoded 0.0.0.0 src_ip — "
        "5-tuple extraction regressed to skeleton behaviour"
    )


def test_reads_hook_and_pf_from_state(bt_source: str):
    assert "$state->hook" in bt_source
    assert "$state->pf" in bt_source


def test_only_emits_drop_verdict(bt_source: str):
    # Phase 1.5 only reports DROP. STOLEN/QUEUE are ambiguous.
    # The .bt printf format string uses escaped quotes around DROP.
    assert 'DROP' in bt_source
    assert 'retval != 0' in bt_source


def test_only_ipv4_tcp_scope(bt_source: str):
    # Phase 1.5 scope: IPv4 (NFPROTO_IPV4 = 2) and TCP (IP proto 6).
    assert "$pf != 2" in bt_source
    assert "$ip_proto != 6" in bt_source


def test_never_fabricates_chain_or_rule(bt_source: str):
    # Phase 1.5 invariant: no rule handle, no fake chain name.
    # Strip comments before checking so a doc comment mentioning
    # "rule_handle (never)" doesn't falsely trip the assertion.
    code_only = re.sub(r"/\*.*?\*/", "", bt_source, flags=re.DOTALL)
    code_only = re.sub(r"//.*", "", code_only)
    assert "rule_handle" not in code_only
    assert "rule_number" not in code_only
    # chain_name is emitted as an empty string only.
    assert "chain_name" in bt_source


def test_flow_filter_placeholder_present(bt_source: str):
    # BpftraceBackend._build_program substitutes {{FILTER}} with the
    # in-kernel guard expression from FlowFilter.as_bpftrace_guard().
    assert "{{FILTER}}" in bt_source


def test_backend_loads_only_this_program_in_phase_1_5():
    from linuxnetlens.backends.bpftrace import _PROGRAM_FILES
    assert _PROGRAM_FILES == ("nf_verdict.bt",), (
        "Phase 1.5 backend must load only the production-quality "
        "nf_verdict.bt program; the other .bt files are skeletons."
    )

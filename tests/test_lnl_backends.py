"""Tests for linuxnetlens.backends."""

from __future__ import annotations

from pathlib import Path

import pytest

from linuxnetlens.backends import detect_backend, list_backends
from linuxnetlens.backends.simulated import SimulatedBackend


FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "linuxnetlens"


def test_simulated_backend_is_always_available():
    backend = SimulatedBackend()
    assert backend.available() is True
    assert backend.describe().startswith("simulated")


def test_simulated_backend_reads_fixture_file():
    backend = SimulatedBackend(replay_path=str(FIXTURES / "blocked_nft.json"))
    events = backend.capture()
    kinds = {e.kind.value for e in events}
    assert "nf_verdict" in kinds
    assert "process" in kinds


def test_simulated_backend_rejects_missing_file():
    with pytest.raises(FileNotFoundError):
        SimulatedBackend(replay_path=str(FIXTURES / "does_not_exist.json"))


def test_list_backends_includes_bpftrace_and_simulated():
    backends = list_backends()
    assert "bpftrace" in backends
    assert "simulated" in backends


def test_detect_backend_falls_back_to_simulated_on_windows():
    """
    On Windows / when bpftrace is unavailable, detect_backend must
    still return something usable (SimulatedBackend).
    """
    backend = detect_backend()
    assert backend is not None
    assert backend.available()


def test_detect_backend_with_replay_forces_simulated():
    backend = detect_backend(replay_path=str(FIXTURES / "unknown_empty.json"))
    assert backend.name == "simulated"


def test_bpftrace_backend_reports_unavailable_on_non_linux(monkeypatch):
    """
    Even when bpftrace is somehow in PATH, the backend must refuse
    to run on non-posix platforms.
    """
    import os

    if os.name == "posix":
        pytest.skip("only meaningful on non-posix")

    from linuxnetlens.backends.bpftrace import BpftraceBackend
    backend = BpftraceBackend(bpftrace_path="/usr/bin/bpftrace")
    assert backend.available() is False


def test_bpftrace_backend_strips_missing_probe_blocks(monkeypatch):
    """
    Regression: if a kprobe symbol is not exported by the running kernel
    (e.g. ipt_do_table on RHEL 8.10 with iptables-nft), the corresponding
    block in nf_verdict.bt must be excised before the program is loaded,
    otherwise bpftrace fails to attach and the run produces 0 events.
    """
    from linuxnetlens.backends.bpftrace import BpftraceBackend
    from linuxnetlens.flow import FlowFilter

    backend = BpftraceBackend(bpftrace_path="/usr/bin/bpftrace")

    # Simulate: nft_do_chain present, ipt_do_table absent.
    def fake_available(self, symbol: str) -> bool:
        return symbol == "nft_do_chain"

    monkeypatch.setattr(
        BpftraceBackend, "_kprobe_available", fake_available
    )

    program = backend._build_program(
        FlowFilter.parse("tcp:*:*->192.0.2.1:12345")
    )

    # Strip comments before checking so the file's header docstring
    # (which mentions probe names) doesn't cause a false positive.
    import re as _re
    code = _re.sub(r"/\*.*?\*/", "", program, flags=_re.DOTALL)

    # The nft block must remain; the ipt block must be gone.
    assert "kprobe:nft_do_chain" in code
    assert "kprobe:ipt_do_table" not in code
    # Walker booleans still referenced in the emitter path — they will
    # simply stay 0 when the corresponding probe never fires.
    assert "@lnl_ipt_seen" in program


def test_bpftrace_backend_keeps_all_probe_blocks_when_available(monkeypatch):
    from linuxnetlens.backends.bpftrace import BpftraceBackend
    from linuxnetlens.flow import FlowFilter

    backend = BpftraceBackend(bpftrace_path="/usr/bin/bpftrace")
    monkeypatch.setattr(
        BpftraceBackend, "_kprobe_available", lambda self, sym: True
    )

    program = backend._build_program(
        FlowFilter.parse("tcp:*:*->192.0.2.1:12345")
    )

    import re as _re
    code = _re.sub(r"/\*.*?\*/", "", program, flags=_re.DOTALL)

    assert "kprobe:nft_do_chain" in code
    assert "kprobe:ipt_do_table" in code

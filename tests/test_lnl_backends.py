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

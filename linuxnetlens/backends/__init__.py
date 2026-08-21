"""
LinuxNetLens backend registry and detection.

Detection is lazy: importing this module never touches the kernel
or subprocess. Only ``detect_backend()`` triggers checks.

Phase 1 backends:

    - ``simulated`` : JSON replay, always available.
    - ``bpftrace``  : subprocess to /usr/bin/bpftrace with in-kernel
                       flow filtering. Requires root on Linux.

BCC and libbpf backends are Phase 2.
"""

from __future__ import annotations

from typing import List, Optional

from linuxnetlens.backends.base import BpfBackend
from linuxnetlens.backends.simulated import SimulatedBackend


_BACKEND_PRIORITY = ("bpftrace", "simulated")


def list_backends() -> List[str]:
    return list(_BACKEND_PRIORITY)


def _try_bpftrace() -> Optional[BpfBackend]:

    try:
        from linuxnetlens.backends.bpftrace import BpftraceBackend
    except Exception:
        return None

    try:
        backend = BpftraceBackend()
        if backend.available():
            return backend
    except Exception:
        return None

    return None


def detect_backend(
    preferred: Optional[str] = None,
    replay_path: Optional[str] = None,
) -> BpfBackend:
    """
    Return the best available backend.

    - ``replay_path`` forces SimulatedBackend and is always honoured.
    - ``preferred`` chooses a backend if available; otherwise auto.
    - Never raises; falls back to ``SimulatedBackend`` on hosts
      without eBPF.
    """

    if replay_path:
        return SimulatedBackend(replay_path=replay_path)

    if preferred == "bpftrace":
        backend = _try_bpftrace()
        if backend is not None:
            return backend

    if preferred == "simulated":
        return SimulatedBackend()

    # Auto-detect.
    backend = _try_bpftrace()
    if backend is not None:
        return backend

    return SimulatedBackend()


__all__ = [
    "BpfBackend",
    "SimulatedBackend",
    "detect_backend",
    "list_backends",
]

"""
LinuxNetLens: on-demand Linux network root-cause analysis.

Phase 1 MVP. Provides:

    - 5-tuple FlowTable
    - SocketRegistry with PID/process/socket/netns attribution
    - Typed eBPF event model (DropEvent, TcpStateEvent, TcpResetEvent,
      NfVerdictEvent, ProcessEvent)
    - VerdictLedger per flow
    - TCP lifecycle observation (connect, SYN, retransmit, RST, timeout)
    - Kernel skb drop-reason interpretation
    - Netfilter DROP/REJECT evidence (hook / verdict; chain only when
      the kernel reports it reliably)
    - Four-outcome classifier: BLOCKED / NO_RESPONSE / RESET / UNKNOWN
    - Evidence-based root-cause attribution with confidence scoring

Design invariants:

    - Never claims LOCAL_BLOCKED without kernel evidence
      (an explicit netfilter verdict or a "blocked-family" skb reason).
    - Never equates xdp_exception with XDP_DROP.
    - Never claims an exact nftables chain/rule unless the kernel
      probe observed it; falls back to "netfilter (backend unknown)".
    - Never derives PID from sock_alloc alone.
    - Runs on demand, briefly, filtered by the requested flow.
"""

from linuxnetlens.attribution import (
    AttributionResult,
    RootCauseAttributor,
    run_attribution,
)
from linuxnetlens.backends import detect_backend, list_backends
from linuxnetlens.events import (
    Certainty,
    DropEvent,
    EventKind,
    NfVerdict,
    NfVerdictEvent,
    ProcessEvent,
    ResetDirection,
    TcpResetEvent,
    TcpState,
    TcpStateEvent,
)
from linuxnetlens.flow import FlowFilter, FlowKey, FlowTable
from linuxnetlens.models import Diagnosis, DropLocation, Hypothesis, Outcome
from linuxnetlens.outcome import OutcomeClassifier
from linuxnetlens.socket_registry import SocketRegistry
from linuxnetlens.verdict_ledger import VerdictLedger


__version__ = "0.1.0"


__all__ = [
    "__version__",
    "AttributionResult",
    "Certainty",
    "Diagnosis",
    "DropEvent",
    "DropLocation",
    "EventKind",
    "FlowFilter",
    "FlowKey",
    "FlowTable",
    "Hypothesis",
    "NfVerdict",
    "NfVerdictEvent",
    "Outcome",
    "OutcomeClassifier",
    "ProcessEvent",
    "ResetDirection",
    "RootCauseAttributor",
    "SocketRegistry",
    "TcpResetEvent",
    "TcpState",
    "TcpStateEvent",
    "VerdictLedger",
    "detect_backend",
    "list_backends",
    "run_attribution",
]

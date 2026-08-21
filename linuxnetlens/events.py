"""
LinuxNetLens typed eBPF event model.

Each backend converts its raw kernel output into one of these typed
events. Downstream code (FlowTable, SocketRegistry, VerdictLedger,
OutcomeClassifier, RootCauseAttributor) only ever sees these types.

Certainty is tagged on every event so the attributor and the
classifier can honestly refuse to overclaim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Union

from linuxnetlens.flow import FlowKey


class EventKind(str, Enum):
    """Discriminator for the typed event union."""

    SKB_DROP = "skb_drop"
    TCP_STATE = "tcp_state"
    TCP_RETRANSMIT = "tcp_retransmit"
    TCP_RESET = "tcp_reset"
    NF_VERDICT = "nf_verdict"
    PROCESS = "process"


class Certainty(str, Enum):
    """
    How reliably an event or annotation was obtained.

    - OBSERVED: read directly from a kernel probe at the exact call
      site (e.g., tracepoint arg, LSM hook argument).
    - INFERRED: derived from another observed event within the
      same capture (e.g., sk->pid mapping applied to a later packet
      event).
    - ASSUMED: reconstructed from user-space state after the fact
      (e.g., ss/lsof/proc reconciliation).
    """

    OBSERVED = "observed"
    INFERRED = "inferred"
    ASSUMED = "assumed"


class TcpState(str, Enum):
    """Kernel TCP states, matching inet_sock_set_state tracepoint."""

    CLOSE = "CLOSE"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    NEW_SYN_RECV = "NEW_SYN_RECV"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def coerce(cls, value: Any) -> "TcpState":
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value)
            except ValueError:
                return cls.UNKNOWN
        return cls.UNKNOWN


class ResetDirection(str, Enum):
    """Which side originated a TCP RST."""

    LOCAL = "local"
    REMOTE = "remote"


class NfVerdict(str, Enum):
    """
    Coarse netfilter verdict.

    We only ever emit DROP or REJECT when the return value from
    nf_hook_slow was < 0 (drop) and, in the REJECT case, an ICMP
    reject was observed on the same skb; otherwise use DROP.
    """

    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    STOLEN = "STOLEN"
    QUEUE = "QUEUE"
    REPEAT = "REPEAT"
    UNKNOWN = "UNKNOWN"


# ----------------------------------------------------------------------
# Typed event dataclasses
# ----------------------------------------------------------------------


@dataclass
class _BaseEvent:
    """
    Fields shared by every typed event.

    Not intended for direct instantiation.
    """

    timestamp: float

    flow: Optional[FlowKey] = None

    cpu: Optional[int] = None

    pid: Optional[int] = None

    comm: Optional[str] = None

    netns_ino: Optional[int] = None

    certainty: Certainty = Certainty.OBSERVED

    probe: str = ""

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DropEvent(_BaseEvent):
    """
    kfree_skb / equivalent: a packet was released by the kernel.

    ``drop_reason`` is the SKB_DROP_REASON_* string when the kernel
    exposes it (Linux >= 5.17, some RHEL 8 backports); empty otherwise.
    """

    kind: EventKind = EventKind.SKB_DROP

    drop_reason: str = ""

    kernel_function: str = ""


@dataclass
class TcpStateEvent(_BaseEvent):
    """A TCP state transition from sock:inet_sock_set_state."""

    kind: EventKind = EventKind.TCP_STATE

    old_state: TcpState = TcpState.UNKNOWN

    new_state: TcpState = TcpState.UNKNOWN


@dataclass
class TcpRetransmitEvent(_BaseEvent):
    """One tcp:tcp_retransmit_skb firing."""

    kind: EventKind = EventKind.TCP_RETRANSMIT

    segment_count: int = 1

    rto_fired: bool = False


@dataclass
class TcpResetEvent(_BaseEvent):
    """tcp:tcp_send_reset or tcp:tcp_receive_reset."""

    kind: EventKind = EventKind.TCP_RESET

    direction: ResetDirection = ResetDirection.LOCAL


@dataclass
class NfVerdictEvent(_BaseEvent):
    """
    A netfilter hook return (nf_hook_slow kretprobe).

    We record only what the kernel reliably provides:

    - ``hook``: PRE_ROUTING / LOCAL_IN / FORWARD / LOCAL_OUT /
      POST_ROUTING (from nf_hook_state->hook).
    - ``pf``: NFPROTO_IPV4 / NFPROTO_IPV6 / NFPROTO_BRIDGE.
    - ``verdict``: NfVerdict.
    - ``nft_walker_seen``: True if kprobe:nft_do_chain fired for the
      same skb inside this hook run.
    - ``ipt_walker_seen``: True if kprobe:ipt_do_table fired.
    - ``chain_name``: only populated when nft_do_chain arg was read
      reliably; empty string otherwise.

    We deliberately never populate a rule handle or number.
    """

    kind: EventKind = EventKind.NF_VERDICT

    hook: str = ""

    pf: str = ""

    verdict: NfVerdict = NfVerdict.UNKNOWN

    nft_walker_seen: bool = False

    ipt_walker_seen: bool = False

    chain_name: str = ""


@dataclass
class ProcessEvent(_BaseEvent):
    """
    A connect(), bind(), or accept() syscall observation.

    Used by SocketRegistry to attach a PID to a flow with OBSERVED
    certainty from a process context, not from softirq.
    """

    kind: EventKind = EventKind.PROCESS

    syscall: str = ""


# Union alias used throughout the module.
Event = Union[
    DropEvent,
    TcpStateEvent,
    TcpRetransmitEvent,
    TcpResetEvent,
    NfVerdictEvent,
    ProcessEvent,
]


# ----------------------------------------------------------------------
# Serialization helpers (used by SimulatedBackend + JSON reports)
# ----------------------------------------------------------------------


def event_to_dict(event: Event) -> Dict[str, Any]:
    """Turn a typed event into a JSON-safe dict."""

    base: Dict[str, Any] = {
        "kind": event.kind.value,
        "timestamp": event.timestamp,
        "certainty": event.certainty.value,
        "probe": event.probe,
        "cpu": event.cpu,
        "pid": event.pid,
        "comm": event.comm,
        "netns_ino": event.netns_ino,
        "metadata": dict(event.metadata),
    }

    if event.flow is not None:
        base["flow"] = event.flow.to_dict()

    if isinstance(event, DropEvent):
        base["drop_reason"] = event.drop_reason
        base["kernel_function"] = event.kernel_function

    elif isinstance(event, TcpStateEvent):
        base["old_state"] = event.old_state.value
        base["new_state"] = event.new_state.value

    elif isinstance(event, TcpRetransmitEvent):
        base["segment_count"] = event.segment_count
        base["rto_fired"] = event.rto_fired

    elif isinstance(event, TcpResetEvent):
        base["direction"] = event.direction.value

    elif isinstance(event, NfVerdictEvent):
        base["hook"] = event.hook
        base["pf"] = event.pf
        base["verdict"] = event.verdict.value
        base["nft_walker_seen"] = event.nft_walker_seen
        base["ipt_walker_seen"] = event.ipt_walker_seen
        base["chain_name"] = event.chain_name

    elif isinstance(event, ProcessEvent):
        base["syscall"] = event.syscall

    return base


def event_from_dict(data: Dict[str, Any]) -> Event:
    """
    Rehydrate a typed event from a dict.

    Unknown ``kind`` values are rejected with ValueError so
    fixtures fail loudly rather than silently degrading.
    """

    kind = EventKind(data["kind"])

    common = dict(
        timestamp=float(data.get("timestamp", 0.0)),
        flow=FlowKey.from_dict(data["flow"]) if data.get("flow") else None,
        cpu=data.get("cpu"),
        pid=data.get("pid"),
        comm=data.get("comm"),
        netns_ino=data.get("netns_ino"),
        certainty=Certainty(data.get("certainty", Certainty.OBSERVED.value)),
        probe=data.get("probe", "") or "",
        metadata=dict(data.get("metadata") or {}),
    )

    if kind is EventKind.SKB_DROP:
        return DropEvent(
            drop_reason=data.get("drop_reason", "") or "",
            kernel_function=data.get("kernel_function", "") or "",
            **common,
        )

    if kind is EventKind.TCP_STATE:
        return TcpStateEvent(
            old_state=TcpState.coerce(data.get("old_state")),
            new_state=TcpState.coerce(data.get("new_state")),
            **common,
        )

    if kind is EventKind.TCP_RETRANSMIT:
        return TcpRetransmitEvent(
            segment_count=int(data.get("segment_count", 1)),
            rto_fired=bool(data.get("rto_fired", False)),
            **common,
        )

    if kind is EventKind.TCP_RESET:
        return TcpResetEvent(
            direction=ResetDirection(
                data.get("direction", ResetDirection.LOCAL.value)
            ),
            **common,
        )

    if kind is EventKind.NF_VERDICT:
        return NfVerdictEvent(
            hook=data.get("hook", "") or "",
            pf=data.get("pf", "") or "",
            verdict=NfVerdict(data.get("verdict", NfVerdict.UNKNOWN.value)),
            nft_walker_seen=bool(data.get("nft_walker_seen", False)),
            ipt_walker_seen=bool(data.get("ipt_walker_seen", False)),
            chain_name=data.get("chain_name", "") or "",
            **common,
        )

    if kind is EventKind.PROCESS:
        return ProcessEvent(
            syscall=data.get("syscall", "") or "",
            **common,
        )

    raise ValueError(f"Unhandled EventKind: {kind}")

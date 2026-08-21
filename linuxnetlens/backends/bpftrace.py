"""
bpftrace subprocess backend for LinuxNetLens.

Phase 1.5 scope
---------------

Only ONE end-to-end eBPF path is enabled:

    Application → TCP flow → Netfilter DROP → LinuxNetLens BLOCKED

That path is served by ``programs/nf_verdict.bt``, which uses BTF-driven
struct-field access to extract a real 5-tuple from the ``sk_buff`` at
``kretprobe:nf_hook_slow`` when the verdict is ``NF_DROP``.

The other four ``.bt`` files (``skb_drop_reasons``, ``tcp_lifecycle``,
``tcp_reset``, ``socket_owner``) remain in the tree as **skeletons** for
future phases and are intentionally not loaded here — several of them still
contain placeholder field accesses that would fail bpftrace compilation on a
real kernel.

Requires:

    - Linux (RHEL 8.5+ or RHEL 9)
    - ``bpftrace`` in $PATH
    - Kernel BTF at ``/sys/kernel/btf/vmlinux`` (default on RHEL 9)
    - CAP_BPF + CAP_PERFMON (or root)

On any missing prerequisite the backend advertises itself as unavailable so
the CLI falls back to SimulatedBackend gracefully.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from linuxnetlens.backends.base import BpfBackend
from linuxnetlens.events import (
    Certainty,
    DropEvent,
    Event,
    EventKind,
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


_PROGRAMS_DIR = Path(__file__).resolve().parent.parent / "programs"

# Phase 1.5: only the netfilter-verdict program is production-quality.
# The other four .bt files under programs/ are skeletons for later phases.
_PROGRAM_FILES = (
    "nf_verdict.bt",
)


class BpftraceBackend(BpfBackend):

    name = "bpftrace"

    def __init__(self, bpftrace_path: Optional[str] = None):
        self._bpftrace = bpftrace_path or shutil.which("bpftrace")

    # ------------------------------------------------------------------
    # BpfBackend interface
    # ------------------------------------------------------------------

    def available(self) -> bool:

        if os.name != "posix":
            return False

        if self._bpftrace is None:
            return False

        if not _PROGRAMS_DIR.exists():
            return False

        for name in _PROGRAM_FILES:
            if not (_PROGRAMS_DIR / name).exists():
                return False

        return True

    def describe(self) -> str:

        return f"bpftrace ({self._bpftrace or 'not found'})"

    def capture(
        self,
        duration: float = 10.0,
        flow_filter: Optional[FlowFilter] = None,
    ) -> List[Event]:

        if not self.available():
            raise RuntimeError(
                "bpftrace backend is not available on this host"
            )

        program = self._build_program(flow_filter)

        assert self._bpftrace is not None

        proc = subprocess.Popen(
            [self._bpftrace, "-f", "json", "-e", program],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            stdout, _ = proc.communicate(timeout=duration + 5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            stdout, _ = proc.communicate()

        events: List[Event] = []

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(record, dict):
                continue

            if record.get("type") != "printf":
                continue

            payload = record.get("data")
            if not isinstance(payload, str):
                continue

            try:
                obj = json.loads(payload.strip())
            except json.JSONDecodeError:
                continue

            event = self._decode(obj)
            if event is not None:
                events.append(event)

        return events

    # ------------------------------------------------------------------
    # Program assembly
    # ------------------------------------------------------------------

    def _build_program(self, flow_filter: Optional[FlowFilter]) -> str:

        guard = (
            flow_filter.as_bpftrace_guard()
            if flow_filter is not None
            else "1"
        )

        sources: List[str] = []
        for name in _PROGRAM_FILES:
            body = (_PROGRAMS_DIR / name).read_text(encoding="utf-8")
            body = body.replace("{{FILTER}}", guard)
            sources.append(body)

        return "\n\n".join(sources)

    # ------------------------------------------------------------------
    # Event decoding
    # ------------------------------------------------------------------

    def _decode(self, obj: dict) -> Optional[Event]:

        kind_str = obj.get("kind")
        if not isinstance(kind_str, str):
            return None

        try:
            kind = EventKind(kind_str)
        except ValueError:
            return None

        flow = self._decode_flow(obj.get("flow"))
        common = self._decode_common(obj)

        if kind is EventKind.SKB_DROP:
            return DropEvent(
                flow=flow,
                drop_reason=obj.get("drop_reason") or "",
                kernel_function=obj.get("kernel_function") or "",
                **common,
            )

        if kind is EventKind.TCP_STATE:
            return TcpStateEvent(
                flow=flow,
                old_state=TcpState.coerce(obj.get("old_state", "")),
                new_state=TcpState.coerce(obj.get("new_state", "")),
                **common,
            )

        if kind is EventKind.TCP_RETRANSMIT:
            return TcpRetransmitEvent(
                flow=flow,
                segment_count=int(obj.get("segment_count", 1)),
                rto_fired=bool(obj.get("rto_fired", False)),
                **common,
            )

        if kind is EventKind.TCP_RESET:
            direction_raw = obj.get("direction", "local")
            try:
                direction = ResetDirection(direction_raw)
            except ValueError:
                direction = ResetDirection.LOCAL
            return TcpResetEvent(
                flow=flow,
                direction=direction,
                **common,
            )

        if kind is EventKind.NF_VERDICT:
            verdict_raw = obj.get("verdict", "unknown")
            try:
                verdict = NfVerdict(verdict_raw)
            except ValueError:
                verdict = NfVerdict.UNKNOWN
            return NfVerdictEvent(
                flow=flow,
                hook=obj.get("hook") or "",
                pf=obj.get("pf") or "",
                verdict=verdict,
                nft_walker_seen=bool(obj.get("nft_walker_seen", False)),
                ipt_walker_seen=bool(obj.get("ipt_walker_seen", False)),
                chain_name=obj.get("chain_name") or "",
                **common,
            )

        if kind is EventKind.PROCESS:
            return ProcessEvent(
                flow=flow,
                syscall=obj.get("syscall") or "",
                **common,
            )

        return None

    @staticmethod
    def _decode_flow(raw) -> Optional[FlowKey]:

        if not isinstance(raw, dict):
            return None

        try:
            return FlowKey.from_dict(raw)
        except Exception:
            return None

    @staticmethod
    def _decode_common(obj: dict) -> dict:

        certainty_raw = obj.get("certainty", "observed")
        try:
            certainty = Certainty(certainty_raw)
        except ValueError:
            certainty = Certainty.OBSERVED

        return {
            "timestamp": float(obj.get("timestamp", 0.0)),
            "cpu": obj.get("cpu"),
            "pid": obj.get("pid"),
            "comm": obj.get("comm") or "",
            "netns_ino": obj.get("netns_ino"),
            "certainty": certainty,
            "probe": obj.get("probe") or "",
            "metadata": obj.get("metadata") or {},
        }

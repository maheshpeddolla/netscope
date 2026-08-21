"""
Terminal report formatter for LinuxNetLens.

The output layout matches the LinuxNetLens Phase 1 diagnostic
example exactly:

    LinuxNetLens Network Diagnosis
    ================================

    Source       : <ip>:<port>
    Destination  : <ip>:<port>
    Protocol     : <TCP|UDP|...>
    Process      : <comm>
    PID          : <pid>

    Result       : <Outcome>

    Blocked By   : <nftables|iptables|netfilter>
    Hook         : <hook>
    Chain        : <chain>       (only when observed)
    Action       : <DROP|REJECT>

    Confidence   : Outcome <n>%  |  Attribution <m>%

The "Blocked By" section is only rendered when the outcome is
BLOCKED and the required kernel evidence is present.
"""

from __future__ import annotations

from io import StringIO
from typing import List, Optional

from linuxnetlens.attribution import AttributionResult
from linuxnetlens.models import Diagnosis, DropLocation, Outcome


def format_result(result: AttributionResult) -> str:
    """Render an ``AttributionResult`` for terminal output."""

    buf = StringIO()

    if not result.diagnoses:
        buf.write("LinuxNetLens Network Diagnosis\n")
        buf.write("================================\n\n")
        buf.write("No diagnoses to display.\n")
        return buf.getvalue()

    for idx, diagnosis in enumerate(result.diagnoses):
        if idx > 0:
            buf.write("\n" + ("-" * 32) + "\n\n")
        _format_diagnosis(buf, diagnosis)

    _format_footer(buf, result)

    return buf.getvalue()


def _format_diagnosis(buf: StringIO, diagnosis: Diagnosis) -> None:

    src, dst = _split_flow(diagnosis.flow_summary)
    proto = _proto_from_flow(diagnosis.flow_summary)

    buf.write("LinuxNetLens Network Diagnosis\n")
    buf.write("================================\n\n")

    buf.write(f"Source       : {src or '(unknown)'}\n")
    buf.write(f"Destination  : {dst or '(unknown)'}\n")
    buf.write(f"Protocol     : {proto}\n")
    buf.write(f"Process      : {diagnosis.process or '(unknown)'}\n")
    buf.write(
        f"PID          : {diagnosis.pid if diagnosis.pid is not None else '(unknown)'}\n"
    )

    buf.write("\n")
    buf.write(f"Result       : {_outcome_label(diagnosis.outcome)}\n")

    firewall = diagnosis.metadata.get("firewall") if diagnosis.metadata else None
    if diagnosis.outcome is Outcome.BLOCKED and firewall:
        buf.write("\n")
        buf.write(f"Blocked By   : {firewall.get('backend', 'netfilter')}\n")
        if firewall.get("hook"):
            buf.write(f"Hook         : {firewall['hook']}\n")
        if firewall.get("chain"):
            buf.write(f"Chain        : {firewall['chain']}\n")
        buf.write(
            f"Action       : {firewall.get('verdict', 'drop').upper()}\n"
        )

    reset = diagnosis.metadata.get("reset") if diagnosis.metadata else None
    if diagnosis.outcome is Outcome.RESET and reset:
        buf.write("\n")
        buf.write(f"Reset Direction : {reset.get('direction', 'unknown')}\n")
        buf.write(f"Reset Count     : {reset.get('count', 1)}\n")

    buf.write("\n")
    buf.write(
        f"Confidence   : Outcome {diagnosis.outcome_confidence}%  |  "
        f"Attribution {diagnosis.attribution_confidence}% "
        f"({_location_label(diagnosis.location)})\n"
    )

    if diagnosis.evidence:
        buf.write("\n")
        buf.write("Evidence:\n")
        for line in diagnosis.evidence:
            buf.write(f"  - {line}\n")

    if diagnosis.recommendations:
        buf.write("\n")
        buf.write("Recommendations:\n")
        for rec in diagnosis.recommendations:
            buf.write(f"  - {rec}\n")


def _format_footer(buf: StringIO, result: AttributionResult) -> None:

    buf.write("\n")
    buf.write("-" * 32 + "\n")
    buf.write(f"Backend      : {result.backend}\n")
    buf.write(f"Events       : {result.total_events}\n")
    buf.write(f"Matched flows: {result.matched_flows}\n")
    if result.flow_filter:
        buf.write(f"Flow filter  : {result.flow_filter}\n")
    for warning in result.warnings:
        buf.write(f"WARNING      : {warning}\n")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _outcome_label(outcome: Outcome) -> str:
    return {
        Outcome.BLOCKED: "BLOCKED (drop observed on the local guest)",
        Outcome.NO_RESPONSE: "NO_RESPONSE (transmitted, no reply seen)",
        Outcome.RESET: "RESET (TCP RST observed)",
        Outcome.UNKNOWN: "UNKNOWN (insufficient evidence)",
    }[outcome]


def _location_label(location: DropLocation) -> str:
    return location.value


def _split_flow(summary: str) -> tuple[str, str]:
    """
    Split ``proto src_ip:src_port -> dst_ip:dst_port`` into
    ``(src, dst)`` display strings.
    """

    if not summary:
        return "", ""

    if "->" not in summary:
        return summary, ""

    left, right = summary.split("->", 1)

    left = left.strip()
    right = right.strip()

    # Drop the leading proto token if present.
    parts = left.split(" ", 1)
    if len(parts) == 2:
        left = parts[1]

    return left, right


def _proto_from_flow(summary: str) -> str:

    if not summary:
        return "(unknown)"

    token = summary.split(" ", 1)[0]

    return token.upper() if token else "(unknown)"

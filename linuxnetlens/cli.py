"""
LinuxNetLens command-line interface.

Subcommands:

    linuxnetlens diagnose   [--flow SPEC] [--replay PATH] [--duration N]
                            [--backend NAME] [--confirm-broad]
                            [--json]

    linuxnetlens info

Reachable as ``python -m linuxnetlens.cli`` or, once installed, as
the ``linuxnetlens`` console script.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from linuxnetlens.attribution import AttributionResult, RootCauseAttributor
from linuxnetlens.backends import detect_backend, list_backends
from linuxnetlens.flow import FlowFilter
from linuxnetlens.report import format_result


# ----------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="linuxnetlens",
        description=(
            "LinuxNetLens: on-demand Linux network root-cause analysis "
            "for VMs and containers."
        ),
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the LinuxNetLens version and exit.",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ---- diagnose --------------------------------------------------
    diagnose = subparsers.add_parser(
        "diagnose",
        help="Capture eBPF events and attribute the failure of a flow.",
    )
    diagnose.add_argument(
        "--flow",
        help=(
            "Flow filter, e.g. 'tcp:10.0.0.1:*->10.0.0.2:443' "
            "or '*:*:*->10.0.0.2:443'. Use 'any' for a broad capture."
        ),
    )
    diagnose.add_argument(
        "--replay",
        help="Replay events from a JSON file instead of running eBPF.",
    )
    diagnose.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Capture window in seconds (default: 10).",
    )
    diagnose.add_argument(
        "--backend",
        choices=list_backends(),
        help="Force a specific backend.",
    )
    diagnose.add_argument(
        "--confirm-broad",
        action="store_true",
        help=(
            "Required when no flow filter (or a broad 'any' filter) "
            "is used, to guard against firehose captures."
        ),
    )
    diagnose.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON report instead of the text report.",
    )

    # ---- info ------------------------------------------------------
    subparsers.add_parser(
        "info",
        help="Show detected backends and capabilities.",
    )

    return parser


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------


def cmd_info() -> int:

    print("LinuxNetLens: available backends")
    print("--------------------------------")

    for name in list_backends():
        marker = "  "
        if name == "bpftrace":
            backend = detect_backend(preferred="bpftrace")
            marker = "* " if backend.name == "bpftrace" else "  "
        elif name == "simulated":
            marker = "* "  # always available
        print(f"{marker}{name}")

    active = detect_backend()
    print()
    print(f"Auto-selected backend: {active.describe()}")

    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:

    flow_filter: Optional[FlowFilter] = None

    if args.flow:
        try:
            flow_filter = FlowFilter.parse(args.flow)
        except ValueError as exc:
            print(f"linuxnetlens: invalid --flow spec: {exc}", file=sys.stderr)
            return 2

    is_broad = flow_filter is None or flow_filter.is_broad()

    if is_broad and not args.confirm_broad and not args.replay:
        print(
            "linuxnetlens: refusing broad capture without --confirm-broad.\n"
            "             Provide --flow or pass --confirm-broad explicitly.",
            file=sys.stderr,
        )
        return 2

    backend = detect_backend(
        preferred=args.backend,
        replay_path=args.replay,
    )

    try:
        events = backend.capture(
            duration=args.duration,
            flow_filter=flow_filter,
        )
    except Exception as exc:  # pragma: no cover - defensive
        print(f"linuxnetlens: capture failed: {exc}", file=sys.stderr)
        return 3

    result = RootCauseAttributor().attribute(
        events,
        backend_name=backend.describe(),
        flow_filter=flow_filter,
    )

    if args.json:
        print(json.dumps(_result_to_dict(result), indent=2))
    else:
        print(format_result(result))

    return 0


def _result_to_dict(result: AttributionResult) -> dict:

    return {
        "backend": result.backend,
        "total_events": result.total_events,
        "matched_flows": result.matched_flows,
        "flow_filter": result.flow_filter,
        "warnings": list(result.warnings),
        "diagnoses": [
            {
                "title": d.title,
                "outcome": d.outcome.value,
                "location": d.location.value,
                "outcome_confidence": d.outcome_confidence,
                "attribution_confidence": d.attribution_confidence,
                "severity": d.severity,
                "flow_summary": d.flow_summary,
                "process": d.process,
                "pid": d.pid,
                "evidence": list(d.evidence),
                "recommendations": list(d.recommendations),
                "metadata": d.metadata,
            }
            for d in result.diagnoses
        ],
    }


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from linuxnetlens import __version__
        print(f"linuxnetlens {__version__}")
        return 0

    if args.command == "info":
        return cmd_info()

    if args.command == "diagnose":
        return cmd_diagnose(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

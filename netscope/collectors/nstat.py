"""
NSTAT Collector
"""

from netscope.utils.command import run_command
from netscope.parsers.nstat import parse_nstat
from netscope.rules.nstat import analyze_nstat


def collect_nstat():

    result = run_command(["nstat", "-az"])

    if not result.success:
        return {
            "available": False,
            "statistics": {},
            "findings": [],
        }

    stats = parse_nstat(result.stdout)

    findings = analyze_nstat(stats)

    return {
        "available": True,
        "statistics": stats,
        "findings": findings,
    }
"""
Ethtool Collector
"""

from netscope.parsers.ethtool import parse_statistics
from netscope.rules.network import analyze_ethtool_stats
from netscope.utils.command import run_command
from netscope.utils.network import get_interfaces


def collect_ethtool():

    report = {}

    for iface in get_interfaces():

        print(f"[+] Collecting ethtool data for {iface}")

        stats_result = run_command(["ethtool", "-S", iface])

        stats = parse_statistics(stats_result.stdout)

        findings = analyze_ethtool_stats(iface, stats)

        report[iface] = {
            "driver": run_command(["ethtool", "-i", iface]).stdout,
            "features": run_command(["ethtool", "-k", iface]).stdout,
            "rings": run_command(["ethtool", "-g", iface]).stdout,
            "statistics": stats,
            "findings": findings,
        }

    return report
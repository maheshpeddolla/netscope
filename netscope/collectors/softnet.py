"""
Softnet Collector
"""

from pathlib import Path

from netscope.parsers.softnet import parse_softnet


def collect_softnet():

    softnet = Path("/proc/net/softnet_stat")

    if not softnet.exists():
        return {
            "available": False,
            "cpus": []
        }

    raw = softnet.read_text().splitlines()

    return {
        "available": True,
        "cpus": parse_softnet(raw)
    }
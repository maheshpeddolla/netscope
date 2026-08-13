"""
Collector Registry

Every collector must be registered here.
"""

from netscope.collectors.system import collect_system
from netscope.collectors.connectivity import collect_connectivity
from netscope.collectors.ethtool import collect_ethtool
from netscope.collectors.softnet import collect_softnet
from netscope.collectors.nstat import collect_nstat

COLLECTORS = {
    "system": {
        "description": "Collect basic system information",
        "function": collect_system,
        "output": "system.json",
    },
    "connectivity": {
        "description": "Collect connectivity troubleshooting data",
        "function": collect_connectivity,
        "output": "connectivity.json",
    },
    "ethtool": {
        "description": "Collect NIC driver and statistics",
        "function": collect_ethtool,
        "output": "ethtool.json",
    },
    "softnet": {
        "description": "Collect softnet statistics",
        "function": collect_softnet,
        "output": "softnet.json",
    },
    "nstat": {
        "description": "Collect network statistics using nstat",
        "function": collect_nstat,
        "output": "nstat.json",
    },
}
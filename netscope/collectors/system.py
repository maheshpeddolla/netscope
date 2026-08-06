"""
System Collector
"""

import platform
import socket


def collect_system():

    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
    }
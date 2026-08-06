"""
Connectivity Collector
"""

from netscope.utils.command import run_command


def collect_connectivity():

    data = {}

    commands = {
        "hostname": ["hostname"],
        "kernel": ["uname", "-a"],
        "interfaces": ["ip", "-br", "addr"],
        "routes": ["ip", "route"],
        "rules": ["ip", "rule"],
        "neighbors": ["ip", "neigh"],
        "tcp": ["ss", "-tuna"],
    }

    for name, command in commands.items():

        print(f"[+] Collecting {name}")

        result = run_command(command)

        data[name] = {
            "success": result.success,
            "command": result.command,
            "output": result.stdout,
            "stderr": result.stderr,
            "return_code": result.return_code,
            "duration_ms": result.duration_ms,
        }

    return data
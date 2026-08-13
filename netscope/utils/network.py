"""
Network utility functions.
"""

from pathlib import Path

from netscope.utils.command import run_command


def get_interfaces() -> list[str]:
    """
    Return a list of physical network interfaces.

    Strategy:
    1. Read /sys/class/net (Linux native)
    2. Fall back to 'ip -o link show'
    """

    sys_class_net = Path("/sys/class/net")

    # Preferred method
    if sys_class_net.exists():

        interfaces = []

        for iface in sys_class_net.iterdir():

            if iface.name == "lo":
                continue

            interfaces.append(iface.name)

        return sorted(interfaces)

    # Fallback
    result = run_command(["ip", "-o", "link", "show"])

    if not result.success:
        return []

    interfaces = []

    for line in result.stdout.splitlines():

        parts = line.split(":")

        if len(parts) < 2:
            continue

        iface = parts[1].strip()

        if iface == "lo":
            continue

        interfaces.append(iface)

    return sorted(interfaces)
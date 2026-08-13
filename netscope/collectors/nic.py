"""
NIC statistics collector.

Collects interface RX/TX counters using `ip -s link`.

The collector is intentionally lightweight and uses the
existing command execution framework.
"""

from netscope.utils.command import run_command


def collect_nic_stats():
    """
    Collect NIC statistics from `ip -s link`.

    Returns:
        Dictionary containing command result and parsed
        interface statistics.
    """

    result = run_command("ip -s link")

    if not result.success:
        return {
            "available": False,
            "error": result.stderr,
            "interfaces": {},
        }

    interfaces = {}

    current_interface = None
    section = None

    lines = result.output.splitlines()

    for line in lines:

        stripped = line.strip()

        # Interface header.
        if line and not line.startswith(" ") and ":" in line:

            parts = line.split(":", 2)

            if len(parts) >= 2:
                current_interface = parts[1].strip()
                interfaces[current_interface] = {
                    "rx": {},
                    "tx": {},
                }

            section = None
            continue

        if current_interface is None:
            continue

        if stripped.startswith("RX:"):
            section = "rx"
            continue

        if stripped.startswith("TX:"):
            section = "tx"
            continue

        if section not in ("rx", "tx"):
            continue

        # Counter header.
        if stripped.startswith("bytes"):
            continue

        values = stripped.split()

        if len(values) < 6:
            continue

        try:

            if section == "rx":

                interfaces[current_interface]["rx"] = {
                    "bytes": int(values[0]),
                    "packets": int(values[1]),
                    "errors": int(values[2]),
                    "dropped": int(values[3]),
                    "missed": int(values[4]),
                    "mcast": int(values[5]),
                }

            else:

                interfaces[current_interface]["tx"] = {
                    "bytes": int(values[0]),
                    "packets": int(values[1]),
                    "errors": int(values[2]),
                    "dropped": int(values[3]),
                    "carrier": int(values[4]),
                    "collisions": int(values[5]),
                }

        except ValueError:
            continue

    return {
        "available": True,
        "interfaces": interfaces,
    }
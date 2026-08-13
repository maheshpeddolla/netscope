"""
Linux softnet statistics monitor.

Reads /proc/net/softnet_stat and provides
before/after counter comparison for live
packet-drop detection.
"""

from pathlib import Path


SOFTNET_STAT = Path("/proc/net/softnet_stat")


def read_softnet_stat(path=SOFTNET_STAT):
    """
    Read /proc/net/softnet_stat.

    Returns:
        Dictionary containing per-CPU softnet counters.
    """

    if not path.exists():
        return {
            "available": False,
            "reason": "/proc/net/softnet_stat not available",
            "cpus": [],
        }

    cpus = []

    try:
        with path.open("r") as file:

            for cpu_id, line in enumerate(file):

                fields = line.split()

                if not fields:
                    continue

                if len(fields) < 3:
                    continue

                processed = int(fields[0], 16)
                dropped = int(fields[1], 16)
                time_squeeze = int(fields[2], 16)

                cpus.append(
                    {
                        "cpu": cpu_id,
                        "processed": processed,
                        "dropped": dropped,
                        "time_squeeze": time_squeeze,
                    }
                )

    except (OSError, ValueError) as exc:

        return {
            "available": False,
            "reason": str(exc),
            "cpus": [],
        }

    return {
        "available": True,
        "cpus": cpus,
    }


def compare_softnet(before, after):
    """
    Compare two softnet snapshots.

    Calculates the increase in:
    - processed
    - dropped
    - time_squeeze

    Args:
        before: First softnet snapshot.
        after: Second softnet snapshot.

    Returns:
        Dictionary containing per-CPU counter deltas.
    """

    if not before.get("available"):
        return {
            "available": False,
            "reason": "Before snapshot unavailable",
            "cpus": [],
        }

    if not after.get("available"):
        return {
            "available": False,
            "reason": "After snapshot unavailable",
            "cpus": [],
        }

    before_cpus = {
        cpu["cpu"]: cpu
        for cpu in before.get("cpus", [])
    }

    after_cpus = {
        cpu["cpu"]: cpu
        for cpu in after.get("cpus", [])
    }

    results = []

    for cpu_id, after_cpu in after_cpus.items():

        before_cpu = before_cpus.get(cpu_id)

        if before_cpu is None:
            continue

        processed_delta = (
            after_cpu["processed"]
            - before_cpu["processed"]
        )

        dropped_delta = (
            after_cpu["dropped"]
            - before_cpu["dropped"]
        )

        time_squeeze_delta = (
            after_cpu["time_squeeze"]
            - before_cpu["time_squeeze"]
        )

        results.append(
            {
                "cpu": cpu_id,
                "processed_delta": max(
                    processed_delta,
                    0
                ),
                "dropped_delta": max(
                    dropped_delta,
                    0
                ),
                "time_squeeze_delta": max(
                    time_squeeze_delta,
                    0
                ),
            }
        )

    return {
        "available": True,
        "cpus": results,
    }


def detect_packet_drops(before, after):
    """
    Detect whether new softnet packet drops occurred
    between two snapshots.

    Returns:
        Dictionary containing packet-drop evidence.
    """

    comparison = compare_softnet(
        before,
        after
    )

    if not comparison.get("available"):
        return {
            "available": False,
            "drops_detected": False,
            "cpus": [],
        }

    dropped_cpus = []

    for cpu in comparison["cpus"]:

        if cpu["dropped_delta"] > 0:

            dropped_cpus.append(cpu)

    return {
        "available": True,
        "drops_detected": len(dropped_cpus) > 0,
        "cpus": dropped_cpus,
    }
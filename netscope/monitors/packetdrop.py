"""
Live packet-drop monitor.

Takes periodic snapshots of Linux softnet statistics,
compares them, and reports newly detected packet drops.
"""

import time

from netscope.monitors.softnet import read_softnet_stat
from netscope.diagnose.packetdrop_engine import diagnose_softnet


def monitor_packet_drops(
    interval=10,
    iterations=1,
    callback=None,
):
    """
    Monitor Linux softnet packet drops.

    Args:
        interval: Seconds between snapshots.
        iterations: Number of observation cycles.
                    Use 0 for continuous monitoring.
        callback: Optional function called with each Diagnosis.

    Returns:
        List of Diagnosis objects.
    """

    results = []

    # Take the initial snapshot.
    before = read_softnet_stat()

    if not before.get("available"):

        diagnosis = diagnose_softnet(
            before,
            before,
        )

        results.append(diagnosis)

        if callback:
            callback(diagnosis)

        return results

    cycle = 0

    while True:

        cycle += 1

        time.sleep(interval)

        after = read_softnet_stat()

        diagnosis = diagnose_softnet(
            before,
            after,
        )

        results.append(diagnosis)

        if callback:
            callback(diagnosis)

        # Prepare for the next observation window.
        before = after

        # iterations=0 means continuous monitoring.
        if iterations != 0 and cycle >= iterations:
            break

    return results
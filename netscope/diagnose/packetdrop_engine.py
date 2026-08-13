"""
Packet Drop Diagnosis Engine

Analyzes packet-drop evidence from Linux networking
and determines the most likely location of the drop.
"""

from netscope.engines.scoring_engine import ScoringEngine
from netscope.models.diagnosis import Diagnosis
from netscope.monitors.softnet import detect_packet_drops


def diagnose(report):
    """
    Analyze packet-drop evidence from an existing report.

    This function is used when collectors have already
    gathered the required information.
    """

    engine = ScoringEngine()

    # --------------------------------------------------
    # Get collector results
    # --------------------------------------------------

    ethtool = report.get("ethtool", {})
    softnet_data = report.get("softnet", {})
    nstat = report.get("nstat", {})

    # ==================================================
    # KERNEL SOFTNET
    # ==================================================

    if softnet_data.get("available"):

        cpus = softnet_data.get("cpus", [])

        dropped = sum(
            cpu.get("dropped", 0)
            for cpu in cpus
        )

        time_squeeze = sum(
            cpu.get("time_squeeze", 0)
            for cpu in cpus
        )

        softnet = engine.hypothesis(
            "Kernel Softnet"
        )

        if dropped > 0:

            softnet.add(
                70,
                f"softnet dropped packets={dropped}"
            )

            softnet.recommend(
                "Check CPU utilization"
            )

            softnet.recommend(
                "Verify IRQ affinity"
            )

            softnet.recommend(
                "Review RSS queues"
            )

            softnet.recommend(
                "Inspect RPS/RFS configuration"
            )

        if time_squeeze > 0:

            softnet.add(
                20,
                f"softnet time_squeeze={time_squeeze}"
            )

            softnet.recommend(
                "Investigate NET_RX softirq CPU pressure"
            )

    # ==================================================
    # TCP STACK
    # ==================================================

    if nstat.get("available"):

        statistics = nstat.get(
            "statistics",
            {}
        )

        retrans = statistics.get(
            "TcpRetransSegs",
            0
        )

        tcp = engine.hypothesis(
            "TCP Stack"
        )

        if retrans > 0:

            tcp.add(
                20,
                f"TCP retransmissions={retrans}"
            )

            tcp.recommend(
                "Check packet loss between source and destination"
            )

            tcp.recommend(
                "Review TCP socket statistics"
            )

    # ==================================================
    # NIC DRIVER
    # ==================================================

    if ethtool.get("available"):

        interfaces = ethtool.get(
            "interfaces",
            []
        )

        driver = engine.hypothesis(
            "NIC Driver"
        )

        for interface in interfaces:

            name = interface.get(
                "name",
                "unknown"
            )

            statistics = interface.get(
                "statistics",
                {}
            )

            rx_dropped = statistics.get(
                "rx_dropped",
                0
            )

            rx_missed = statistics.get(
                "rx_missed_errors",
                0
            )

            rx_errors = statistics.get(
                "rx_errors",
                0
            )

            if rx_dropped > 0:

                driver.add(
                    30,
                    f"{name} rx_dropped={rx_dropped}"
                )

                driver.recommend(
                    "Check RX ring size using ethtool -g"
                )

                driver.recommend(
                    "Review NIC driver statistics using ethtool -S"
                )

            if rx_missed > 0:

                driver.add(
                    50,
                    f"{name} rx_missed_errors={rx_missed}"
                )

                driver.recommend(
                    "Check RX ring buffer capacity"
                )

                driver.recommend(
                    "Review RSS queue configuration"
                )

            if rx_errors > 0:

                driver.add(
                    40,
                    f"{name} rx_errors={rx_errors}"
                )

                driver.recommend(
                    "Review NIC and driver error counters"
                )

    # ==================================================
    # SELECT WINNER
    # ==================================================

    return _build_diagnosis(engine)


def diagnose_softnet(before, after):
    """
    Diagnose live softnet packet drops.

    Compares two /proc/net/softnet_stat snapshots
    and feeds newly observed drops into the scoring
    engine.
    """

    engine = ScoringEngine()

    result = detect_packet_drops(
        before,
        after
    )

    if not result.get("available"):

        return Diagnosis(
            title="Live Packet Drop Investigation",
            location="Unknown",
            confidence=0,
            severity="info",
            evidence=[
                "Softnet statistics unavailable"
            ],
            recommendations=[
                "Verify that /proc/net/softnet_stat exists"
            ],
        )

    softnet = engine.hypothesis(
        "Kernel Softnet"
    )

    if result.get("drops_detected"):

        total_drops = sum(
            cpu["dropped_delta"]
            for cpu in result["cpus"]
        )

        affected_cpus = [
            str(cpu["cpu"])
            for cpu in result["cpus"]
        ]

        softnet.add(
            70,
            (
                f"{total_drops} new softnet packet drops "
                f"detected on CPU(s): "
                f"{', '.join(affected_cpus)}"
            )
        )

        softnet.recommend(
            "Check CPU utilization"
        )

        softnet.recommend(
            "Verify IRQ affinity"
        )

        softnet.recommend(
            "Review RSS queues"
        )

        softnet.recommend(
            "Inspect RPS/RFS configuration"
        )

        softnet.recommend(
            "Investigate NET_RX softirq CPU pressure"
        )

    else:

        return Diagnosis(
            title="Live Packet Drop Investigation",
            location="No Drop Detected",
            confidence=0,
            severity="info",
            evidence=[
                "No new softnet packet drops detected "
                "during the observation window"
            ],
            recommendations=[
                "Continue monitoring if the issue is intermittent",
                "Check NIC, TCP and firewall counters"
            ],
        )

    return _build_diagnosis(
        engine,
        title="Live Packet Drop Investigation"
    )


def _build_diagnosis(
    engine,
    title="Packet Drop Investigation"
):
    """
    Convert scoring-engine results into a Diagnosis object.
    """

    winner = engine.winner()

    if winner is None or winner.score == 0:

        return Diagnosis(
            title=title,
            location="Unknown",
            confidence=0,
            severity="info",
            evidence=[
                "No packet-drop evidence detected"
            ],
            recommendations=[
                "Collect packet capture during the issue",
                "Review application-level errors",
                "Check Azure networking telemetry"
            ],
        )

    confidence = min(
        winner.score,
        100
    )

    if confidence >= 80:

        severity = "critical"

    elif confidence >= 50:

        severity = "warning"

    else:

        severity = "info"

    return Diagnosis(
        title=title,
        location=winner.name,
        confidence=confidence,
        severity=severity,
        evidence=winner.evidence,
        recommendations=winner.recommendations,
    )
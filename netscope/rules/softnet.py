"""
Softnet troubleshooting rules.
"""


def analyze_softnet(cpus):

    findings = []

    for cpu in cpus:

        if cpu["dropped"] > 0:

            findings.append({
                "severity": "warning",
                "cpu": cpu["cpu"],
                "metric": "dropped",
                "value": cpu["dropped"],
                "message": "Kernel dropped packets on this CPU",
                "recommendation": (
                    "Check CPU utilization, RPS/RFS configuration, "
                    "IRQ affinity and NIC RSS queues."
                ),
            })

        if cpu["time_squeeze"] > 0:

            findings.append({
                "severity": "warning",
                "cpu": cpu["cpu"],
                "metric": "time_squeeze",
                "value": cpu["time_squeeze"],
                "message": "NET_RX softirq exhausted its processing budget",
                "recommendation": (
                    "Investigate packet rate, softirq load, and CPU saturation."
                ),
            })

    return findings
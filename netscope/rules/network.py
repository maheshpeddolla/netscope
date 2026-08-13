"""
Network troubleshooting rules.
"""


def analyze_ethtool_stats(interface: str, stats: dict) -> list[dict]:
    """
    Analyze parsed ethtool statistics.
    """

    findings = []

    checks = {
        "rx_dropped": "RX packet drops detected",
        "tx_dropped": "TX packet drops detected",
        "rx_crc_errors": "CRC errors detected",
        "rx_errors": "RX errors detected",
        "tx_errors": "TX errors detected",
    }

    for key, message in checks.items():

        value = stats.get(key, 0)

        if isinstance(value, int) and value > 0:

            findings.append({
                "severity": "warning",
                "interface": interface,
                "metric": key,
                "value": value,
                "message": message,
            })

    return findings
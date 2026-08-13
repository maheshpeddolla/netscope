"""
Rules for nstat
"""


IMPORTANT_COUNTERS = {
    "TcpRetransSegs": "TCP retransmissions detected",
    "TcpExtListenOverflows": "TCP listen queue overflow",
    "TcpExtListenDrops": "TCP SYN drops",
    "IpInDiscards": "IP packet discards",
    "IpOutDiscards": "Outgoing packet discards",
    "IpReasmFails": "Fragment reassembly failures",
}


def analyze_nstat(stats):

    findings = []

    for counter, message in IMPORTANT_COUNTERS.items():

        value = stats.get(counter, 0)

        if value > 0:

            findings.append({
                "severity": "warning",
                "counter": counter,
                "value": value,
                "message": message,
            })

    return findings
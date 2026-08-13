from netscope.rules.network import analyze_ethtool_stats

sample = {
    "rx_packets": 1000,
    "tx_packets": 2000,
    "rx_dropped": 5,
    "tx_dropped": 0,
    "rx_crc_errors": 2,
}

findings = analyze_ethtool_stats("eth0", sample)

for finding in findings:
    print(finding)
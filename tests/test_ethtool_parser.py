from netscope.parsers.ethtool import parse_statistics

sample = """
NIC statistics:
     rx_packets: 12345
     tx_packets: 67890
     rx_dropped: 12
     tx_dropped: 0
     rx_crc_errors: 3
"""

stats = parse_statistics(sample)

print(stats)

assert stats["rx_packets"] == 12345
assert stats["tx_packets"] == 67890
assert stats["rx_dropped"] == 12
assert stats["tx_dropped"] == 0
assert stats["rx_crc_errors"] == 3

print("Parser test passed.")
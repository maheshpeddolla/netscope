from netscope.parsers.nstat import parse_nstat
from netscope.rules.nstat import analyze_nstat

sample = """
TcpRetransSegs          12
TcpExtListenDrops       5
IpInDiscards            3
IpOutDiscards           0
"""

stats = parse_nstat(sample)

print(stats)

findings = analyze_nstat(stats)

print()

for finding in findings:
    print(finding)
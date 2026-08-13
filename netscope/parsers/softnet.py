"""
Parser for /proc/net/softnet_stat
"""


def parse_softnet(raw_lines):
    """
    Parse /proc/net/softnet_stat

    Returns:
        List of dictionaries (one per CPU)
    """

    cpus = []

    for cpu, line in enumerate(raw_lines):

        fields = line.split()

        if len(fields) < 3:
            continue

        cpus.append({
            "cpu": cpu,
            "processed": int(fields[0], 16),
            "dropped": int(fields[1], 16),
            "time_squeeze": int(fields[2], 16),
        })

    return cpus
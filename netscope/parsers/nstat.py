"""
Parser for nstat output
"""


def parse_nstat(output: str):

    stats = {}

    for line in output.splitlines():

        line = line.strip()

        if (
            not line
            or line.startswith("#")
            or line.startswith("Tcp")
            or line.startswith("Ip")
        ):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        key = parts[0]

        try:
            value = int(parts[-1])
        except ValueError:
            continue

        stats[key] = value

    return stats
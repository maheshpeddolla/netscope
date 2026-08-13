"""
Parser for ethtool output.
"""


def parse_statistics(output: str) -> dict:
    """
    Parse 'ethtool -S' output into a dictionary.
    """

    stats = {}

    for line in output.splitlines():

        line = line.strip()

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip()
        value = value.strip()

        try:
            stats[key] = int(value)
        except ValueError:
            stats[key] = value

    return stats
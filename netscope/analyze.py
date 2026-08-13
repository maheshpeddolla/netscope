"""
Simple analyzer entry point.
"""

import json
from pathlib import Path


def analyze_report(path: str):

    report = Path(path)

    with report.open() as f:
        data = json.load(f)

    print("=" * 60)
    print("NetScope Analysis")
    print("=" * 60)

    if not data:
        print("No data found.")
        return

    for iface, details in data.items():

        findings = details.get("findings", [])

        if not findings:
            print(f"[OK] {iface}: No issues detected")
            continue

        print(f"\nInterface: {iface}")

        for finding in findings:

            print(
                f"WARNING: {finding['message']} "
                f"({finding['metric']}={finding['value']})"
            )
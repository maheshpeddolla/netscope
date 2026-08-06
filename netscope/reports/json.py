"""
JSON Report Writer
"""

import json
from pathlib import Path


def write_json(filename: str, data: dict):

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / filename

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    return output_file
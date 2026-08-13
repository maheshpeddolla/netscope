"""
Knowledge Base Loader
"""

from pathlib import Path
import yaml


KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


def load_rule(rule_name: str):

    rule_file = KNOWLEDGE_DIR / f"{rule_name}.yaml"

    if not rule_file.exists():
        return None

    with open(rule_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
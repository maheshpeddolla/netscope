"""
LinuxNetLens core data models.

Kept intentionally decoupled from netscope.models so LinuxNetLens is
self-contained and existing NetScope functionality is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Outcome(str, Enum):
    """
    The four possible outcomes for an observed flow.

    Values are stable strings so they can be serialized directly to
    JSON reports.
    """

    BLOCKED = "BLOCKED"
    NO_RESPONSE = "NO_RESPONSE"
    RESET = "RESET"
    UNKNOWN = "UNKNOWN"


class DropLocation(str, Enum):
    """
    Coarse-grained subsystems LinuxNetLens can attribute drops to.

    Phase 1 exposes only the subsystems we can prove from the kernel
    with the MVP probe set. XDP and TC values exist so we can label
    kernel-reported SKB reasons honestly (they may show up in
    evidence), but the attributor will not select them as the winner
    without explicit skb-reason support in Phase 1.
    """

    UNKNOWN = "Unknown"
    NIC_DRIVER = "NIC Driver"
    SOFTNET = "Kernel Softnet"
    TCP = "TCP Stack"
    FIREWALL = "Firewall (netfilter)"
    APPLICATION = "Application / Socket"
    XDP = "XDP"
    TC = "Traffic Control"


@dataclass
class Hypothesis:
    """A single candidate explanation, accumulated by the attributor."""

    name: str

    score: float = 0.0

    evidence: List[str] = field(default_factory=list)

    recommendations: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    def add(self, score: float, evidence: str) -> None:

        self.score += score

        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def recommend(self, recommendation: str) -> None:

        if recommendation and recommendation not in self.recommendations:
            self.recommendations.append(recommendation)


@dataclass
class Diagnosis:
    """
    LinuxNetLens's per-flow diagnosis.

    Two confidence numbers are exposed:

    - ``outcome_confidence``: how sure we are of the four-outcome
      classification (BLOCKED / NO_RESPONSE / RESET / UNKNOWN).
    - ``attribution_confidence``: how sure we are of the winning
      DropLocation.

    They are computed independently on purpose. It is legitimate to
    be highly confident of the outcome (e.g., NO_RESPONSE) while
    being uncertain which subsystem is responsible.
    """

    title: str

    outcome: Outcome

    location: DropLocation

    outcome_confidence: int

    attribution_confidence: int

    severity: str

    flow_summary: str = ""

    process: str = ""

    pid: int | None = None

    evidence: List[str] = field(default_factory=list)

    recommendations: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

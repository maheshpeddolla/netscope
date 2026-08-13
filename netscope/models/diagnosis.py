from dataclasses import dataclass, field
from typing import List


@dataclass
class Diagnosis:

    title: str

    location: str

    confidence: int

    severity: str

    evidence: List[str] = field(default_factory=list)

    recommendations: List[str] = field(default_factory=list)
from dataclasses import dataclass, field
from typing import List


@dataclass
class Hypothesis:
    name: str
    score: int = 0
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def add(self, score: int, evidence: str):
        self.score += score
        self.evidence.append(evidence)

    def recommend(self, recommendation: str):
        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)
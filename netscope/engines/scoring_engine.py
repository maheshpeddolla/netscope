"""
Generic Scoring Engine
"""

from netscope.models.hypothesis import Hypothesis


class ScoringEngine:

    def __init__(self):
        self.hypotheses = {}

    def hypothesis(self, name):

        if name not in self.hypotheses:
            self.hypotheses[name] = Hypothesis(name)

        return self.hypotheses[name]

    def winner(self):

        if not self.hypotheses:
            return None

        return max(
            self.hypotheses.values(),
            key=lambda h: h.score
        )

    def ranking(self):

        return sorted(
            self.hypotheses.values(),
            key=lambda h: h.score,
            reverse=True
        )
"""
Correlation Engine
"""


def calculate_health(findings):

    score = 100

    for finding in findings:

        severity = finding.get("severity", "info")

        if severity == "critical":
            score -= 20

        elif severity == "warning":
            score -= 5

    return max(score, 0)


def correlate(report):

    findings = []

    for collector in report.values():

        if not isinstance(collector, dict):
            continue

        findings.extend(
            collector.get("findings", [])
        )

    return {

        "health_score": calculate_health(findings),

        "total_findings": len(findings),

        "findings": findings

    }
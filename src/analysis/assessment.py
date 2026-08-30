#!/usr/bin/env python3
"""Shared threat-level and action helpers used by the multi-agent system and tests."""

from typing import List


def determine_threat_level(risk_score: float) -> str:
    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def recommended_actions(attack_type: str, risk_score: float, confidence: float = 0.5) -> List[str]:
    attack = (attack_type or "").lower()
    actions: List[str] = []

    if risk_score >= 8.0 and confidence > 0.7:
        actions.extend([
            "Block the source IP immediately",
            "Isolate affected hosts",
            "Trigger incident response",
            "Preserve forensic evidence",
        ])
    elif risk_score >= 6.0:
        actions.extend([
            "Increase monitoring on the source and target",
            "Review related WAF / IDS alerts",
            "Validate whether the payload reached a vulnerable service",
        ])
    elif risk_score >= 4.0:
        actions.extend([
            "Log and correlate with recent alerts from the same source",
            "Confirm the finding is not a scanner false positive",
        ])
    else:
        actions.extend([
            "Record the event for trend analysis",
            "No immediate containment required",
        ])

    if "sql" in attack:
        actions.extend(["Enable SQL-injection WAF rules", "Audit database query logs"])
    elif "xss" in attack or "cross-site" in attack:
        actions.extend(["Tighten output encoding / CSP", "Review session-cookie flags"])
    elif "command" in attack or "rce" in attack:
        actions.extend(["Disable unused command execution paths", "Inspect process audit logs"])
    elif "scan" in attack:
        actions.extend(["Rate-limit the source", "Check whether an internet-wide scanner is involved"])

    # Preserve order while dropping empties / duplicates
    seen = set()
    unique = []
    for item in actions:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    return unique

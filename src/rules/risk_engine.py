"""
risk_engine.py — Severity-based risk scoring.

Observed scoring pattern (reverse-engineered from alerts.csv):
  critical  →  90 pts per rule
  high      →  60 pts per rule
  medium    →  30 pts per rule
  low       →  10 pts per rule

Multiple matched rules accumulate; total is capped at 100.
Inactive-account escalation adds +10 (also capped at 100).
"""

# Points contributed by each severity level when a rule fires
SEVERITY_SCORE: dict[str, int] = {
    "critical": 90,
    "high":     60,
    "medium":   30,
    "low":      10,
}

# Bonus applied when the acting account is marked inactive
INACTIVE_BONUS: int = 10


def compute_risk_score(severities: list[str], is_inactive: bool = False) -> int:
    """
    Sum severity scores, apply inactive bonus, and cap at 100.

    Parameters
    ----------
    severities  : List of severity strings (one per matched rule).
    is_inactive : True if the user's is_active flag is False.

    Returns
    -------
    int — aggregate risk score, 0–100.
    """
    total = sum(SEVERITY_SCORE.get(s, 30) for s in severities)
    if is_inactive and total > 0:
        total += INACTIVE_BONUS
    return min(100, total)


def get_risk_level(score: int) -> str:
    """
    Convert a numeric risk score to a human-readable risk level.

    Ranges match the severity_risk_score_guide in rules.json:
      CRITICAL  80–100
      HIGH      60–79
      MEDIUM    30–59
      LOW       0–29
    """
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
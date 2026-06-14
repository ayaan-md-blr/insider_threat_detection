from dataclasses import dataclass


@dataclass
class Alert:

    user_id: str

    rule_id: str

    severity: str

    risk_score: int

    timestamp: str
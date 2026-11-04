from __future__ import annotations

from datetime import date, timedelta

# Days to remediate after detection. Tune to the organisation's vulnerability management policy.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def due_date(severity: str, start: date | str) -> str | None:
    days = SLA_DAYS.get(severity)
    if days is None:
        return None
    if isinstance(start, str):
        start = date.fromisoformat(start)
    return (start + timedelta(days=days)).isoformat()

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}
SEVERITY_LABELS = {
    "critical": "Критическая",
    "high": "Высокая",
    "medium": "Средняя",
    "low": "Низкая",
    "info": "Инфо",
}

STATUSES = ("open", "in_progress", "fixed", "risk_accepted", "false_positive")
ACTIVE_STATUSES = ("open", "in_progress")
CLOSED_STATUSES = ("fixed", "risk_accepted", "false_positive")
STATUS_LABELS = {
    "open": "Открыта",
    "in_progress": "В работе",
    "fixed": "Устранена",
    "risk_accepted": "Риск принят",
    "false_positive": "Ложное срабатывание",
}

# CWE classes narrow enough to say two scanners found the same issue at the same endpoint.
# Broad ones (CWE-200, CWE-693, ...) cover many unrelated checks, so those stay per scanner rule.
CORRELATABLE_CWES = frozenset(
    {"22", "77", "78", "79", "89", "94", "352", "434", "502", "601", "611", "639", "798", "918"}
)


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


@dataclass
class Finding:
    """One issue reported by a scanner, already normalised by its parser."""

    tool: str
    rule_id: str
    title: str
    severity: str
    location: str
    cwe: str | None = None
    cve: str | None = None
    cvss_vector: str | None = None
    params: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    asset: str | None = None  # parser's guess (e.g. the host); --asset overrides it

    @property
    def weakness(self) -> str:
        """What the finding is, independent of the scanner that reported it."""
        if self.cve:
            return self.cve
        if self.cwe in CORRELATABLE_CWES:
            return f"CWE-{self.cwe}"
        return f"{self.tool}:{self.rule_id}"


@dataclass
class ParseResult:
    tool: str
    findings: list[Finding]

"""SARIF 2.1.0, the common output of SAST tools (Semgrep, Bandit, CodeQL, gosec, ...)."""

from __future__ import annotations

import re

from ..cvss import severity_from_score
from ..models import Finding, ParseResult

LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
CWE_TAG = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _text(message: dict | None) -> str:
    return ((message or {}).get("text") or "").strip()


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "sarif"


def _severity(result: dict, rule: dict) -> str:
    # GitHub code scanning convention: a CVSS-like number in rule properties wins over the level.
    score = (rule.get("properties") or {}).get("security-severity")
    if score is not None:
        try:
            return severity_from_score(float(score))
        except (TypeError, ValueError):
            pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return LEVEL.get(level, "medium")


def _cwe(*tag_lists: list) -> str | None:
    for tags in tag_lists:
        for tag in tags or []:
            match = CWE_TAG.search(str(tag))
            if match:
                return match.group(1)
    return None


def parse(data: dict) -> ParseResult:
    findings = []
    tool_name = None
    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = _slug(driver.get("name") or "sarif")
        tool_name = tool_name or tool
        rules = driver.get("rules") or []
        rules_by_id = {rule.get("id"): rule for rule in rules}

        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or ""
            rule = rules_by_id.get(rule_id)
            index = result.get("ruleIndex")
            if rule is None and isinstance(index, int) and 0 <= index < len(rules):
                rule = rules[index]
                rule_id = rule_id or rule.get("id", "")
            rule = rule or {}

            location = ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
            uri = (location.get("artifactLocation") or {}).get("uri") or "<unknown>"
            region = location.get("region") or {}
            line = region.get("startLine")
            snippet = ((region.get("snippet") or {}).get("text") or "").strip()
            where = f"{uri}:{line}" if line else uri

            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    title=_text(rule.get("shortDescription")) or rule.get("name") or rule_id,
                    severity=_severity(result, rule),
                    location=where,
                    cwe=_cwe((rule.get("properties") or {}).get("tags"), (result.get("properties") or {}).get("tags")),
                    description=_text(result.get("message")) or _text(rule.get("fullDescription")),
                    remediation=_text(rule.get("help")),
                    evidence=f"{where}\n{snippet}" if snippet else where,
                    references=[rule["helpUri"]] if rule.get("helpUri") else [],
                )
            )
    return ParseResult(tool_name or "sarif", findings)

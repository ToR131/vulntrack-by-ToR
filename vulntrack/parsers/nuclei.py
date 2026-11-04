"""ProjectDiscovery Nuclei results (nuclei -jsonl, or -json-export which writes a JSON array)."""

from __future__ import annotations

from ..models import SEVERITIES, Finding, ParseResult
from ._common import host_of, normalize_url, query_params


def _first(value) -> str | None:
    """Nuclei writes classification ids either as a list or as a comma-separated string."""
    if isinstance(value, list):
        return str(value[0]).strip() if value else None
    if isinstance(value, str) and value.strip():
        return value.split(",")[0].strip()
    return None


def parse(data: list | dict) -> ParseResult:
    records = [data] if isinstance(data, dict) else data
    findings = []
    for record in records:
        info = record.get("info") or {}
        classification = info.get("classification") or {}
        template = record.get("template-id", "unknown")
        matcher = record.get("matcher-name")
        url = record.get("matched-at") or record.get("host") or ""

        cwe = _first(classification.get("cwe-id"))
        cve = _first(classification.get("cve-id"))
        severity = str(info.get("severity", "info")).lower()
        references = info.get("reference") or []

        evidence = [f"Шаблон {template} сработал на {url}"]
        if record.get("extracted-results"):
            evidence.append("Извлечено: " + "; ".join(map(str, record["extracted-results"])))
        if record.get("curl-command"):
            evidence.append(f"Воспроизведение: {record['curl-command']}")

        findings.append(
            Finding(
                tool="nuclei",
                rule_id=f"{template}:{matcher}" if matcher else template,
                title=f"{info.get('name') or template}: {matcher}" if matcher else info.get("name") or template,
                severity=severity if severity in SEVERITIES else "info",
                location=normalize_url(url),
                cwe=cwe.lower().removeprefix("cwe-") if cwe else None,
                cve=cve.upper() if cve else None,
                cvss_vector=classification.get("cvss-metrics") or None,
                params=query_params(url),
                description=(info.get("description") or "").strip(),
                remediation=(info.get("remediation") or "").strip(),
                evidence="\n".join(evidence),
                references=[references] if isinstance(references, str) else list(references),
                asset=host_of(url),
            )
        )
    return ParseResult("nuclei", findings)

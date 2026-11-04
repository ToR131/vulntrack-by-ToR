"""OWASP ZAP "Traditional JSON" report (zap-baseline.py -J, Report > Export > JSON)."""

from __future__ import annotations

from ..models import Finding, ParseResult
from ._common import extract_urls, host_of, normalize_url, strip_html

RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
CONFIDENCE_FALSE_POSITIVE = "0"  # set when an analyst marks the alert as a false positive in ZAP


def parse(data: dict) -> ParseResult:
    findings = []
    for site in data.get("site", []):
        site_url = site.get("@name", "")
        for alert in site.get("alerts", []):
            if str(alert.get("confidence")) == CONFIDENCE_FALSE_POSITIVE:
                continue
            cwe = str(alert.get("cweid", "")).strip()
            for instance in alert.get("instances") or [{"uri": site_url}]:
                uri = instance.get("uri") or site_url
                param = instance.get("param")
                evidence = [f"{instance.get('method', 'GET')} {uri}"]
                if param:
                    evidence.append(f"Параметр: {param}")
                if instance.get("attack"):
                    evidence.append(f"Атака: {instance['attack']}")
                if instance.get("evidence"):
                    evidence.append(f"Признак в ответе: {instance['evidence']}")
                if alert.get("otherinfo"):
                    evidence.append(strip_html(alert["otherinfo"]))
                findings.append(
                    Finding(
                        tool="zap",
                        rule_id=str(alert.get("pluginid", "")),
                        title=alert.get("name") or alert.get("alert") or "ZAP alert",
                        severity=RISK.get(str(alert.get("riskcode")), "info"),
                        location=normalize_url(uri),
                        cwe=cwe if cwe.isdigit() and cwe != "0" else None,
                        params=[param] if param else [],
                        description=strip_html(alert.get("desc")),
                        remediation=strip_html(alert.get("solution")),
                        evidence="\n".join(evidence),
                        references=extract_urls(alert.get("reference")),
                        asset=host_of(uri),
                    )
                )
    return ParseResult("zap", findings)

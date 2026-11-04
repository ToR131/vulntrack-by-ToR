"""CVSS v3.x base score calculator, following section 7 of the FIRST v3.1 specification."""

from __future__ import annotations

import math
from dataclasses import dataclass

BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weighs more when the attack crosses a security scope.
PR_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


@dataclass(frozen=True)
class CvssResult:
    vector: str
    score: float
    severity: str


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def roundup(value: float) -> float:
    """Round up to one decimal, immune to float noise (v3.1 spec, Appendix A)."""
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000
    return (math.floor(as_int / 10_000) + 1) / 10


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    prefix, *parts = vector.strip().split("/")
    if prefix not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError(f"поддерживается только CVSS 3.0/3.1, получено: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            raise ValueError(f"некорректный CVSS-вектор: {vector!r}")
        metrics[key] = value
    for key in BASE_METRICS:
        if metrics.get(key) not in WEIGHTS[key]:
            raise ValueError(f"в CVSS-векторе нет корректной метрики {key}: {vector!r}")
    return prefix, metrics


def base_score(vector: str) -> CvssResult:
    version, m = parse_vector(vector)
    changed = m["S"] == "C"

    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = (PR_SCOPE_CHANGED if changed else WEIGHTS["PR"])[m["PR"]]
    exploitability = 8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * pr * WEIGHTS["UI"][m["UI"]]

    # v3.0 used a plain ceiling; v3.1 replaced it with the float-safe roundup.
    rnd = roundup if version == "CVSS:3.1" else (lambda x: math.ceil(x * 10) / 10)
    if impact <= 0:
        score = 0.0
    elif changed:
        score = rnd(min(1.08 * (impact + exploitability), 10))
    else:
        score = rnd(min(impact + exploitability, 10))

    normalized = version + "/" + "/".join(f"{key}:{m[key]}" for key in BASE_METRICS)
    return CvssResult(normalized, score, severity_from_score(score))

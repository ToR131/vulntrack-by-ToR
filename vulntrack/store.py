"""SQLite-backed findings register: deduplication, status lifecycle, SLA and audit trail."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from datetime import date

from .cvss import base_score
from .models import (
    ACTIVE_STATUSES,
    CLOSED_STATUSES,
    SEVERITIES,
    SEVERITY_LABELS,
    SEVERITY_RANK,
    STATUS_LABELS,
    STATUSES,
    Finding,
    ParseResult,
    max_severity,
)
from .sla import due_date

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY,
    fingerprint     TEXT NOT NULL UNIQUE,
    asset           TEXT NOT NULL,
    title           TEXT NOT NULL,
    weakness        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    severity_locked INTEGER NOT NULL DEFAULT 0,
    cvss_vector     TEXT,
    cvss_score      REAL,
    cwe             TEXT,
    cve             TEXT,
    location        TEXT NOT NULL,
    params          TEXT NOT NULL DEFAULT '',
    tools           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    refs            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    owner           TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    sla_start       TEXT NOT NULL,
    due_date        TEXT,
    closed_at       TEXT,
    reopen_count    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    day        TEXT NOT NULL,
    kind       TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_asset_status ON findings(asset, status);
"""


class FindingNotFound(LookupError):
    pass


@dataclass
class ImportStats:
    new: int = 0
    known: int = 0
    correlated: int = 0  # already reported by another scanner
    reopened: int = 0
    duplicates: int = 0  # collapsed inside this report
    closed: int = 0


@dataclass
class Summary:
    active: dict[str, int] = field(default_factory=lambda: {s: 0 for s in SEVERITIES})
    closed: dict[str, int] = field(default_factory=lambda: {s: 0 for s in CLOSED_STATUSES})
    overdue: int = 0
    mttr_days: float | None = None  # mean time to remediate, over fixed findings


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def fingerprint(asset: str, finding: Finding) -> str:
    raw = f"{asset}|{finding.weakness}|{finding.location}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _split(value: str | None) -> list[str]:
    return [item for item in (value or "").split(",") if item]


def _join(values) -> str:
    return ",".join(sorted(set(values)))


def _event(conn, finding_id: int, today: date, kind: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO events (finding_id, day, kind, detail) VALUES (?, ?, ?, ?)",
        (finding_id, today.isoformat(), kind, detail),
    )


def _update(conn, finding_id: int, changes: dict) -> None:
    # Column names come from this module only, values are bound parameters.
    assignments = ", ".join(f"{column} = ?" for column in changes)
    conn.execute(f"UPDATE findings SET {assignments} WHERE id = ?", [*changes.values(), finding_id])


def get_finding(conn, finding_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        raise FindingNotFound(f"находка #{finding_id} не найдена")
    return row


def _scored(finding: Finding) -> tuple[str | None, float | None, str]:
    if finding.cvss_vector:
        try:
            result = base_score(finding.cvss_vector)
            return result.vector, result.score, result.severity
        except ValueError:
            pass  # a malformed vector from a scanner should not block the import
    return None, None, finding.severity


def _upsert(conn, fp: str, asset: str, finding: Finding, today: date) -> str:
    day = today.isoformat()
    vector, score, severity = _scored(finding)
    row = conn.execute("SELECT * FROM findings WHERE fingerprint = ?", (fp,)).fetchone()

    if row is None:
        cursor = conn.execute(
            """INSERT INTO findings (fingerprint, asset, title, weakness, severity, cvss_vector, cvss_score,
                                     cwe, cve, location, params, tools, description, remediation, evidence,
                                     refs, first_seen, last_seen, sla_start, due_date)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (fp, asset, finding.title, finding.weakness, severity, vector, score, finding.cwe, finding.cve,
             finding.location, _join(finding.params), finding.tool, finding.description, finding.remediation,
             finding.evidence, "\n".join(finding.references), day, day, day, due_date(severity, today)),
        )
        _event(conn, cursor.lastrowid, today, "created", f"обнаружена сканером {finding.tool}")
        return "new"

    tools = _split(row["tools"])
    outcome = "known" if finding.tool in tools else "correlated"
    changes: dict = {
        "last_seen": day,
        "tools": _join(tools + [finding.tool]),
        "params": _join(_split(row["params"]) + finding.params),
    }
    for column in ("description", "remediation", "cwe", "cve"):
        if not row[column] and getattr(finding, column):
            changes[column] = getattr(finding, column)
    refs = row["refs"].splitlines()
    changes["refs"] = "\n".join(refs + [r for r in finding.references if r not in refs])
    if outcome == "correlated" and finding.evidence:
        old = row["evidence"]
        if old and not old.startswith("— "):
            old = f"— {tools[0]}:\n{old}"
        changes["evidence"] = f"{old}\n\n— {finding.tool}:\n{finding.evidence}".strip()

    current = row["severity"]
    if not row["severity_locked"]:  # an analyst's CVSS assessment beats scanner defaults
        if vector and not row["cvss_vector"]:
            changes.update(cvss_vector=vector, cvss_score=score)
        merged = max_severity(current, severity)
        if merged != current:
            changes["severity"] = merged
            _event(conn, row["id"], today, "severity",
                   f"{SEVERITY_LABELS[current]} → {SEVERITY_LABELS[merged]} по данным {finding.tool}")
            current = merged

    sla_start = row["sla_start"]
    if row["status"] == "fixed":
        sla_start = day
        changes.update(status="open", closed_at=None, sla_start=day, reopen_count=row["reopen_count"] + 1)
        _event(conn, row["id"], today, "reopened", f"снова обнаружена сканером {finding.tool}")
        outcome = "reopened"
    if "severity" in changes or "sla_start" in changes:
        changes["due_date"] = due_date(current, sla_start)

    _update(conn, row["id"], changes)
    return outcome


def _set_status(conn, row: sqlite3.Row, status: str, today: date, comment: str | None = None) -> None:
    day = today.isoformat()
    changes: dict = {"status": status}
    if status in CLOSED_STATUSES:
        changes["closed_at"] = day
    elif row["status"] in CLOSED_STATUSES:  # manual reopen restarts the SLA clock
        changes.update(closed_at=None, sla_start=day, reopen_count=row["reopen_count"] + 1,
                       due_date=due_date(row["severity"], day))
    _update(conn, row["id"], changes)
    detail = f"{STATUS_LABELS[row['status']]} → {STATUS_LABELS[status]}"
    _event(conn, row["id"], today, "status", f"{detail}: {comment}" if comment else detail)


def import_report(conn, result: ParseResult, today: date, asset: str | None = None,
                  close_missing: bool = False) -> ImportStats:
    """Merge a scanner report into the register.

    With close_missing, active findings this scanner reported on this asset earlier but not now
    are marked fixed; if a later scan finds them again they are reopened as regressions.
    """
    if close_missing and not asset:
        raise ValueError("--close-missing работает только с явным --asset")
    stats = ImportStats()
    seen: set[str] = set()
    with conn:
        for finding in result.findings:
            finding_asset = asset or finding.asset or "codebase"
            fp = fingerprint(finding_asset, finding)
            outcome = _upsert(conn, fp, finding_asset, finding, today)
            if fp in seen:
                stats.duplicates += 1
                continue
            seen.add(fp)
            setattr(stats, outcome, getattr(stats, outcome) + 1)

        if close_missing:
            placeholders = ", ".join("?" for _ in ACTIVE_STATUSES)
            rows = conn.execute(
                f"SELECT * FROM findings WHERE asset = ? AND status IN ({placeholders})",
                (asset, *ACTIVE_STATUSES),
            ).fetchall()
            for row in rows:
                if row["fingerprint"] not in seen and result.tool in _split(row["tools"]):
                    _set_status(conn, row, "fixed", today, f"не обнаружена при повторном сканировании {result.tool}")
                    stats.closed += 1
    return stats


def update_finding(conn, finding_id: int, today: date, status: str | None = None, cvss: str | None = None,
                   owner: str | None = None, comment: str | None = None) -> sqlite3.Row:
    """Analyst triage: rescore, assign an owner, move through the lifecycle."""
    if status is not None and status not in STATUSES:
        raise ValueError(f"неизвестный статус {status!r}")
    if status in ("risk_accepted", "false_positive") and not comment:
        raise ValueError(f"для статуса «{STATUS_LABELS[status]}» нужен --comment с обоснованием")

    with conn:
        row = get_finding(conn, finding_id)
        if cvss:
            result = base_score(cvss)
            _update(conn, finding_id, {
                "cvss_vector": result.vector,
                "cvss_score": result.score,
                "severity": result.severity,
                "severity_locked": 1,
                "due_date": due_date(result.severity, row["sla_start"]),
            })
            old = row["cvss_score"] if row["cvss_score"] is not None else "—"
            _event(conn, finding_id, today, "rescored",
                   f"CVSS {old} → {result.score} ({SEVERITY_LABELS[result.severity]}), {result.vector}")
        if owner is not None:
            _update(conn, finding_id, {"owner": owner})
            _event(conn, finding_id, today, "owner", owner)
        row = get_finding(conn, finding_id)
        if status and status != row["status"]:
            _set_status(conn, row, status, today, comment)
        elif comment:
            _event(conn, finding_id, today, "comment", comment)
    return get_finding(conn, finding_id)


def list_findings(conn, today: date, statuses=ACTIVE_STATUSES, min_severity: str | None = None,
                  asset: str | None = None, overdue: bool = False) -> list[sqlite3.Row]:
    sql = f"SELECT * FROM findings WHERE status IN ({', '.join('?' for _ in statuses)})"
    params: list = list(statuses)
    if asset:
        sql += " AND asset = ?"
        params.append(asset)
    if overdue:
        sql += " AND due_date IS NOT NULL AND due_date < ?"
        params.append(today.isoformat())
    rows = conn.execute(sql, params).fetchall()
    if min_severity:
        rows = [r for r in rows if SEVERITY_RANK[r["severity"]] >= SEVERITY_RANK[min_severity]]
    return sorted(rows, key=lambda r: (-SEVERITY_RANK[r["severity"]], r["due_date"] or "9999-12-31", r["id"]))


def events_for(conn, finding_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM events WHERE finding_id = ? ORDER BY id", (finding_id,)).fetchall()


def summary(conn, today: date, asset: str | None = None) -> Summary:
    sql, params = "SELECT * FROM findings", []
    if asset:
        sql, params = sql + " WHERE asset = ?", [asset]
    result = Summary()
    durations = []
    for row in conn.execute(sql, params):
        if row["status"] in ACTIVE_STATUSES:
            result.active[row["severity"]] += 1
            if row["due_date"] and row["due_date"] < today.isoformat():
                result.overdue += 1
        else:
            result.closed[row["status"]] += 1
            if row["status"] == "fixed" and row["closed_at"]:
                durations.append((date.fromisoformat(row["closed_at"]) - date.fromisoformat(row["first_seen"])).days)
    if durations:
        result.mttr_days = round(sum(durations) / len(durations), 1)
    return result

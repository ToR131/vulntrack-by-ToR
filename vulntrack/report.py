"""Reports for development teams: HTML (to read), Markdown (to paste into a ticket), CSV (to import).

Scanner output is attacker-controlled (payloads, response bodies), so everything is escaped:
HTML-escaped text, http(s)-only links, CSV cells guarded against formula injection.
"""

from __future__ import annotations

import csv
import io
from datetime import date
from html import escape
from urllib.parse import urlsplit

from .models import CLOSED_STATUSES, SEVERITIES, SEVERITY_LABELS, STATUS_LABELS
from .store import events_for, list_findings, summary

EVENT_LABELS = {
    "created": "Обнаружена",
    "severity": "Критичность",
    "reopened": "Переоткрыта",
    "status": "Статус",
    "rescored": "Оценка CVSS",
    "owner": "Ответственный",
    "comment": "Комментарий",
}

CSS = """
:root { --bg:#ffffff; --fg:#1d1f23; --muted:#5f6670; --line:#e3e5e8; --card:#f6f7f9; --link:#1f5fa8;
        --critical:#b3261e; --high:#c2410c; --medium:#8a6a00; --low:#2f6fb3; --info:#6b7280; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181c; --fg:#e8eaed; --muted:#9aa0a6; --line:#2c3036; --card:#1f2227; --link:#8ab4f8;
          --critical:#f2766b; --high:#ff9b5e; --medium:#e3c04d; --low:#7fb2ec; --info:#9aa0a6; }
}
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 1100px; padding: 24px 16px 64px; background: var(--bg); color: var(--fg);
       font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 36px 0 12px; }
h3 { font-size: 16px; margin: 0 0 6px; }
h4 { font-size: 13px; margin: 14px 0 4px; color: var(--muted); text-transform: uppercase; letter-spacing: .03em; }
a { color: var(--link); }
.sub { color: var(--muted); margin: 0 0 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
.card b { display: block; font-size: 26px; font-variant-numeric: tabular-nums; }
.card span { color: var(--muted); font-size: 13px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600;
       color: var(--bg); white-space: nowrap; }
.sev-critical { background: var(--critical); } .sev-high { background: var(--high); }
.sev-medium { background: var(--medium); } .sev-low { background: var(--low); } .sev-info { background: var(--info); }
.overdue { color: var(--critical); font-weight: 600; }
code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; }
td code { word-break: break-all; }
pre { background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px;
      white-space: pre-wrap; word-break: break-word; margin: 0; }
.finding { border-top: 1px solid var(--line); padding-top: 18px; margin-top: 24px; }
.meta { color: var(--muted); margin: 0 0 10px; }
dl { display: grid; grid-template-columns: 170px 1fr; gap: 4px 16px; margin: 0; }
dt { color: var(--muted); } dd { margin: 0; word-break: break-word; }
ul { margin: 0; padding-left: 20px; }
@media (max-width: 640px) { dl { grid-template-columns: 1fr; } dd { margin-bottom: 6px; } }
"""


def _text(value) -> str:
    return escape(str(value or "")).replace("\n", "<br>")


def _safe_href(url: str) -> str | None:
    return url if urlsplit(url).scheme in ("http", "https") else None


def _link(url: str, label: str | None = None) -> str:
    href = _safe_href(url)
    if href is None:
        return escape(label or url)
    return f'<a href="{escape(href, quote=True)}" rel="noopener noreferrer">{escape(label or url)}</a>'


def _badge(severity: str) -> str:
    return f'<span class="sev sev-{severity}">{SEVERITY_LABELS[severity]}</span>'


def _due(row, today: date) -> tuple[str, bool]:
    if not row["due_date"]:
        return "—", False
    days = (date.fromisoformat(row["due_date"]) - today).days
    if days < 0:
        return f"{row['due_date']} (просрочено на {-days} дн.)", True
    return f"{row['due_date']} (осталось {days} дн.)", False


def _classification(row) -> list[str]:
    items = []
    if row["cve"]:
        items.append(_link(f"https://nvd.nist.gov/vuln/detail/{row['cve']}", row["cve"]))
    if row["cwe"]:
        items.append(_link(f"https://cwe.mitre.org/data/definitions/{row['cwe']}.html", f"CWE-{row['cwe']}"))
    return items


def _finding_html(conn, row, today: date) -> str:
    due, overdue = _due(row, today)
    score = f"CVSS {row['cvss_score']}" if row["cvss_score"] is not None else "CVSS не оценён"
    facts = [
        ("Где", f"<code>{escape(row['location'])}</code>"),
        ("Параметры", escape(row["params"].replace(",", ", ")) if row["params"] else ""),
        ("Классификация", ", ".join(_classification(row))),
        ("CVSS-вектор", f"<code>{escape(row['cvss_vector'])}</code>" if row["cvss_vector"] else ""),
        ("Сканеры", escape(row["tools"].replace(",", ", "))),
        ("Ответственный", escape(row["owner"] or "не назначен")),
        ("Срок по SLA", f'<span class="overdue">{escape(due)}</span>' if overdue else escape(due)),
        ("Впервые / последний раз", f"{row['first_seen']} / {row['last_seen']}"),
        ("Переоткрывалась", f"{row['reopen_count']} раз" if row["reopen_count"] else ""),
    ]
    parts = [
        f'<article class="finding" id="f-{row["id"]}">',
        f"<h3>#{row['id']} {escape(row['title'])}</h3>",
        f'<p class="meta">{_badge(row["severity"])} {score} · {STATUS_LABELS[row["status"]]} · {escape(row["asset"])}</p>',
        "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts if v) + "</dl>",
    ]
    if row["description"]:
        parts.append(f"<h4>Описание</h4><p>{_text(row['description'])}</p>")
    if row["evidence"]:
        parts.append(f"<h4>Как воспроизвести</h4><pre>{escape(row['evidence'])}</pre>")
    if row["remediation"]:
        parts.append(f"<h4>Как исправить</h4><p>{_text(row['remediation'])}</p>")
    refs = [r for r in row["refs"].splitlines() if r]
    if refs:
        parts.append("<h4>Ссылки</h4><ul>" + "".join(f"<li>{_link(r)}</li>" for r in refs) + "</ul>")
    history = "".join(
        f"<li>{e['day']} · {EVENT_LABELS.get(e['kind'], e['kind'])}: {escape(e['detail'])}</li>"
        for e in events_for(conn, row["id"])
    )
    parts.append(f"<h4>История</h4><ul>{history}</ul></article>")
    return "\n".join(parts)


def render_html(conn, today: date, asset: str | None = None, include_info: bool = False) -> str:
    active = [r for r in list_findings(conn, today, asset=asset) if include_info or r["severity"] != "info"]
    closed = list_findings(conn, today, statuses=CLOSED_STATUSES, asset=asset)
    stats = summary(conn, today, asset)
    scope = escape(asset) if asset else "все активы"

    cards = [(stats.active[s], f"Открыто: {SEVERITY_LABELS[s].lower()}") for s in SEVERITIES if s != "info"]
    cards += [
        (stats.overdue, "Просрочено по SLA"),
        (stats.closed["fixed"], "Устранено"),
        (f"{stats.mttr_days} дн." if stats.mttr_days is not None else "—", "Среднее время устранения"),
    ]

    rows = []
    for r in active:
        due, overdue = _due(r, today)
        rows.append(
            "<tr>"
            f'<td class="num"><a href="#f-{r["id"]}">#{r["id"]}</a></td>'
            f"<td>{_badge(r['severity'])}</td>"
            f'<td class="num">{r["cvss_score"] if r["cvss_score"] is not None else "—"}</td>'
            f"<td>{escape(r['title'])}</td>"
            f"<td><code>{escape(r['location'])}</code></td>"
            f"<td>{STATUS_LABELS[r['status']]}</td>"
            f"<td>{escape(r['owner'] or '—')}</td>"
            f'<td class="num{" overdue" if overdue else ""}">{escape(due)}</td>'
            "</tr>"
        )
    closed_rows = "".join(
        f"<tr><td class=\"num\">#{r['id']}</td><td>{_badge(r['severity'])}</td><td>{escape(r['title'])}</td>"
        f"<td><code>{escape(r['location'])}</code></td><td>{STATUS_LABELS[r['status']]}</td>"
        f"<td class=\"num\">{r['closed_at'] or '—'}</td></tr>"
        for r in closed
    )

    head = "<tr><th>ID</th><th>Критичность</th><th>CVSS</th><th>Уязвимость</th><th>Где</th><th>Статус</th>" \
           "<th>Ответственный</th><th>Срок</th></tr>"
    body = [
        "<!doctype html>",
        '<html lang="ru"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Уязвимости: {scope}</title><style>{CSS}</style></head><body>",
        f"<h1>Отчёт по уязвимостям: {scope}</h1>",
        f'<p class="sub">Сформирован {today.isoformat()} · активных находок: {len(active)}</p>',
        '<section class="cards">' + "".join(f'<div class="card"><b>{v}</b><span>{k}</span></div>' for v, k in cards)
        + "</section>",
        "<h2>Активные уязвимости</h2>",
        f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>'
        if rows else "<p>Активных уязвимостей нет.</p>",
        "<h2>Детали и рекомендации</h2>",
        *(_finding_html(conn, r, today) for r in active),
    ]
    if closed_rows:
        body += [
            "<h2>Закрытые</h2>",
            '<div class="table-wrap"><table><thead><tr><th>ID</th><th>Критичность</th><th>Уязвимость</th>'
            f"<th>Где</th><th>Статус</th><th>Закрыта</th></tr></thead><tbody>{closed_rows}</tbody></table></div>",
        ]
    body.append("</body></html>")
    return "\n".join(body)


def _md(value) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(conn, today: date, asset: str | None = None, include_info: bool = False) -> str:
    active = [r for r in list_findings(conn, today, asset=asset) if include_info or r["severity"] != "info"]
    stats = summary(conn, today, asset)
    counts = ", ".join(f"{SEVERITY_LABELS[s].lower()}: {stats.active[s]}" for s in SEVERITIES if s != "info")
    lines = [
        f"# Отчёт по уязвимостям: {asset or 'все активы'}",
        "",
        f"Сформирован {today.isoformat()}. Открыто — {counts}. Просрочено по SLA: {stats.overdue}. "
        f"Устранено: {stats.closed['fixed']}.",
        "",
        "| ID | Критичность | CVSS | Уязвимость | Где | Статус | Срок |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in active:
        due, overdue = _due(r, today)
        lines.append(
            f"| #{r['id']} | {SEVERITY_LABELS[r['severity']]} | {r['cvss_score'] if r['cvss_score'] is not None else '—'} "
            f"| {_md(r['title'])} | `{_md(r['location'])}` | {STATUS_LABELS[r['status']]} "
            f"| {'**' + due + '**' if overdue else due} |"
        )
    for r in active:
        lines += ["", f"## #{r['id']} {_md(r['title'])}", ""]
        lines.append(f"- **Критичность:** {SEVERITY_LABELS[r['severity']]}"
                     + (f", CVSS {r['cvss_score']} (`{r['cvss_vector']}`)" if r["cvss_vector"] else ""))
        lines.append(f"- **Где:** `{_md(r['location'])}`" + (f", параметры: {r['params']}" if r["params"] else ""))
        if r["cwe"] or r["cve"]:
            lines.append("- **Классификация:** " + ", ".join(x for x in (r["cve"], r["cwe"] and f"CWE-{r['cwe']}") if x))
        lines.append(f"- **Сканеры:** {r['tools'].replace(',', ', ')}")
        if r["remediation"]:
            lines.append(f"- **Как исправить:** {_md(r['remediation'])}")
        if r["evidence"]:
            lines += ["", "```text", r["evidence"].replace("```", "'''"), "```"]
    return "\n".join(lines) + "\n"


CSV_COLUMNS = ("id", "asset", "severity", "cvss_score", "cvss_vector", "title", "location", "params", "cwe", "cve",
               "tools", "status", "owner", "first_seen", "last_seen", "due_date", "closed_at", "reopen_count")


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet apps execute cells starting with these characters as formulas (CSV injection).
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_csv(conn, today: date, asset: str | None = None) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for r in list_findings(conn, today, statuses=tuple(STATUS_LABELS), asset=asset):
        writer.writerow([_csv_cell(r[column]) for column in CSV_COLUMNS])
    return out.getvalue()

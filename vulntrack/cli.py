from __future__ import annotations

import argparse
import os
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .cvss import base_score
from .models import CLOSED_STATUSES, SEVERITIES, SEVERITY_LABELS, STATUS_LABELS, STATUSES
from .parsers import PARSERS, load
from .report import render_csv, render_html, render_markdown
from .store import (
    FindingNotFound,
    connect,
    events_for,
    get_finding,
    import_report,
    list_findings,
    summary,
    update_finding,
)

REPORT_DEFAULTS = {"html": "report.html", "md": "report.md", "csv": "findings.csv"}


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(str(cell)) for cell in column) for column in zip(headers, *rows)]
    line = lambda cells: "  ".join(str(c).ljust(w) for c, w in zip(cells, widths)).rstrip()
    return "\n".join([line(headers), line("-" * w for w in widths), *(line(r) for r in rows)])


def cmd_import(args, today: date) -> int:
    result = load(args.report, args.format)
    with connect(args.db) as conn:
        stats = import_report(conn, result, today, asset=args.asset, close_missing=args.close_missing)
    print(f"{args.report.name} ({result.tool}): находок в отчёте {len(result.findings)}")
    print(f"  новых: {stats.new}  уже известных: {stats.known}  связано с другими сканерами: {stats.correlated}")
    print(f"  переоткрыто: {stats.reopened}  дублей в отчёте: {stats.duplicates}  закрыто как устранённые: {stats.closed}")
    return 0


def cmd_list(args, today: date) -> int:
    statuses = (args.status,) if args.status else (STATUSES if args.all else ("open", "in_progress"))
    with connect(args.db) as conn:
        rows = list_findings(conn, today, statuses=statuses, min_severity=args.min_severity,
                             asset=args.asset, overdue=args.overdue)
    if not rows:
        print("Ничего не найдено.")
        return 0
    table = []
    for r in rows:
        due = r["due_date"] or "—"
        if r["due_date"] and r["due_date"] < today.isoformat() and r["status"] not in CLOSED_STATUSES:
            due += " !"
        table.append([
            f"#{r['id']}", SEVERITY_LABELS[r["severity"]],
            "—" if r["cvss_score"] is None else str(r["cvss_score"]),
            STATUS_LABELS[r["status"]], due, _clip(r["title"], 44), _clip(r["location"], 52),
        ])
    print(_table(["ID", "Критичность", "CVSS", "Статус", "Срок", "Уязвимость", "Где"], table))
    print(f"\nВсего: {len(rows)}  («!» — просрочен срок по SLA)")
    return 0


def cmd_show(args, today: date) -> int:
    with connect(args.db) as conn:
        r = get_finding(conn, args.id)
        events = events_for(conn, args.id)
    print(f"#{r['id']} {r['title']}")
    fields = [
        ("Актив", r["asset"]), ("Критичность", SEVERITY_LABELS[r["severity"]]),
        ("CVSS", f"{r['cvss_score']} {r['cvss_vector']}" if r["cvss_vector"] else "не оценён"),
        ("Статус", STATUS_LABELS[r["status"]]), ("Ответственный", r["owner"] or "не назначен"),
        ("Где", r["location"]), ("Параметры", r["params"]), ("CWE", r["cwe"]), ("CVE", r["cve"]),
        ("Сканеры", r["tools"]), ("Срок по SLA", r["due_date"]),
        ("Впервые / последний раз", f"{r['first_seen']} / {r['last_seen']}"),
    ]
    for label, value in fields:
        if value:
            print(f"  {label + ':':<26}{value}")
    for title, value in (("Описание", r["description"]), ("Как воспроизвести", r["evidence"]),
                         ("Как исправить", r["remediation"])):
        if value:
            print(f"\n{title}:\n{value}")
    print("\nИстория:")
    for e in events:
        print(f"  {e['day']}  {e['kind']:<9} {e['detail']}")
    return 0


def cmd_update(args, today: date) -> int:
    with connect(args.db) as conn:
        r = update_finding(conn, args.id, today, status=args.status, cvss=args.cvss,
                           owner=args.owner, comment=args.comment)
    score = f", CVSS {r['cvss_score']}" if r["cvss_score"] is not None else ""
    print(f"#{r['id']}: {STATUS_LABELS[r['status']]}, {SEVERITY_LABELS[r['severity']]}{score}, "
          f"срок {r['due_date'] or '—'}, ответственный {r['owner'] or '—'}")
    return 0


def cmd_report(args, today: date) -> int:
    out = args.out or Path(REPORT_DEFAULTS[args.format])
    with connect(args.db) as conn:
        if args.format == "html":
            content = render_html(conn, today, asset=args.asset, include_info=args.include_info)
        elif args.format == "md":
            content = render_markdown(conn, today, asset=args.asset, include_info=args.include_info)
        else:
            content = render_csv(conn, today, asset=args.asset)
    # BOM lets Excel open the CSV as UTF-8
    out.write_text(content, encoding="utf-8-sig" if args.format == "csv" else "utf-8", newline="")
    print(f"Отчёт сохранён: {out}")
    return 0


def cmd_stats(args, today: date) -> int:
    with connect(args.db) as conn:
        s = summary(conn, today, args.asset)
    print("Открытые уязвимости:")
    for severity in SEVERITIES:
        print(f"  {SEVERITY_LABELS[severity]:<12}{s.active[severity]}")
    print(f"Просрочено по SLA: {s.overdue}")
    print("Закрытые: " + ", ".join(f"{STATUS_LABELS[k].lower()} {v}" for k, v in s.closed.items()))
    print(f"Среднее время устранения: {s.mttr_days if s.mttr_days is not None else '—'} дн.")
    return 0


def cmd_cvss(args, today: date) -> int:
    result = base_score(args.vector)
    print(f"{result.score} {SEVERITY_LABELS[result.severity]}  {result.vector}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulntrack", description="Агрегация и учёт уязвимостей из отчётов сканеров безопасности.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", default=os.environ.get("VULNTRACK_DB", "vulntrack.db"),
                        help="файл базы SQLite (по умолчанию vulntrack.db или $VULNTRACK_DB)")
    parser.add_argument("--today", type=date.fromisoformat, help="дата «сегодня» в формате ГГГГ-ММ-ДД, для демо")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("import", help="загрузить отчёт сканера")
    p.add_argument("report", type=Path)
    p.add_argument("--format", choices=["auto", *PARSERS], default="auto")
    p.add_argument("--asset", help="имя системы; по умолчанию хост из URL или codebase для SAST")
    p.add_argument("--close-missing", action="store_true",
                   help="закрыть находки этого сканера на активе, которых нет в новом отчёте")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("list", help="список находок")
    p.add_argument("--status", choices=STATUSES)
    p.add_argument("--all", action="store_true", help="включая закрытые")
    p.add_argument("--min-severity", choices=SEVERITIES)
    p.add_argument("--asset")
    p.add_argument("--overdue", action="store_true", help="только просроченные по SLA")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="карточка находки с историей")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("update", help="триаж: статус, CVSS, ответственный")
    p.add_argument("id", type=int)
    p.add_argument("--status", choices=STATUSES)
    p.add_argument("--cvss", help="CVSS-вектор, например CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    p.add_argument("--owner", help="команда или человек, который исправляет")
    p.add_argument("--comment", help="обоснование; обязательно для risk_accepted и false_positive")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("report", help="отчёт для команд разработки")
    p.add_argument("--format", choices=list(REPORT_DEFAULTS), default="html")
    p.add_argument("--out", type=Path)
    p.add_argument("--asset")
    p.add_argument("--include-info", action="store_true", help="показывать информационные находки")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("stats", help="сводка и метрики")
    p.add_argument("--asset")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("cvss", help="посчитать CVSS v3.1 по вектору")
    p.add_argument("vector")
    p.set_defaults(func=cmd_cvss)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args, args.today or date.today())
    except (ValueError, FindingNotFound, OSError) as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1

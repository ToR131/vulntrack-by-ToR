from __future__ import annotations

import json
from pathlib import Path

from ..models import ParseResult
from . import nuclei, sarif, zap

PARSERS = {"zap": zap.parse, "nuclei": nuclei.parse, "sarif": sarif.parse}


def decode(text: str):
    text = text.strip()
    if not text:
        raise ValueError("отчёт пустой")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # JSON Lines: one object per line, as written by nuclei -jsonl
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def detect(data) -> str:
    if isinstance(data, dict):
        if "runs" in data:
            return "sarif"
        if "site" in data:
            return "zap"
        if "template-id" in data:
            return "nuclei"
    if isinstance(data, list) and data and isinstance(data[0], dict) and "template-id" in data[0]:
        return "nuclei"
    raise ValueError("не удалось определить формат отчёта, укажите --format")


def load(path: str | Path, fmt: str = "auto") -> ParseResult:
    data = decode(Path(path).read_text(encoding="utf-8-sig"))
    if fmt == "auto":
        fmt = detect(data)
    return PARSERS[fmt](data)

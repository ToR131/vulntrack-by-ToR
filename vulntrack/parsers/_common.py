"""Helpers shared by the report parsers."""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qsl, urlsplit

_BLOCK_END = re.compile(r"</p>|<br\s*/?>|</li>", re.IGNORECASE)
_TAG = re.compile(r"<[^>]+>")
_URL = re.compile(r"https?://[^\s<>\"']+")
_ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.IGNORECASE
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def strip_html(text: str | None) -> str:
    """Turn the HTML fragments scanners put into descriptions into plain text."""
    if not text:
        return ""
    text = _TAG.sub("", _BLOCK_END.sub("\n", text))
    lines = (" ".join(line.split()) for line in html.unescape(text).splitlines())
    return "\n".join(line for line in lines if line)


def extract_urls(text: str | None) -> list[str]:
    return _URL.findall(text or "")


def normalize_url(url: str) -> str:
    """Canonical endpoint: no query or fragment, default port dropped, ids collapsed to {id}.

    /users/42 and /users/43 are the same endpoint, so a finding on both counts once.
    """
    url = url.strip()
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return url
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        return url
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    segments = ["{id}" if _ID_SEGMENT.match(s) else s for s in parts.path.split("/")]
    path = "/".join(segments).rstrip("/") or "/"
    return f"{scheme}://{netloc}{path}"


def query_params(url: str) -> list[str]:
    return sorted({name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def host_of(url: str) -> str | None:
    return urlsplit(url.strip()).hostname

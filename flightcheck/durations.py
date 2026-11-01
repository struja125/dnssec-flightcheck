"""Parsing and formatting of durations ("1d2h", "90m") and plan-relative times."""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone

_UNITS = {"w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1}
_PART = re.compile(r"(\d+(?:\.\d+)?)\s*([wdhms])")


def parse_duration(value) -> int:
    """Parse "1d12h", "90m", "45s", "-2h" or a plain number of seconds into seconds."""
    if isinstance(value, bool):
        raise ValueError(f"invalid duration: {value!r}")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError(f"invalid duration: {value!r}")
        return int(value)
    text = str(value).strip().lower().replace(" ", "")
    if not text:
        raise ValueError("empty duration")
    sign = 1
    if text[0] in "+-":
        sign = -1 if text[0] == "-" else 1
        text = text[1:]
    if text.isdigit():
        return sign * int(text)
    pos = 0
    total = 0.0
    for match in _PART.finditer(text):
        if match.start() != pos:
            raise ValueError(f"invalid duration: {value!r}")
        total += float(match.group(1)) * _UNITS[match.group(2)]
        pos = match.end()
    if pos != len(text) or pos == 0:
        raise ValueError(f"invalid duration: {value!r}")
    return sign * int(round(total))


def format_duration(seconds: float) -> str:
    """Format seconds as a compact human duration, e.g. "1d 2h 5m"."""
    if seconds == math.inf:
        return "forever"
    if seconds == -math.inf:
        return "-forever"
    sign = "-" if seconds < 0 else ""
    rest = int(round(abs(seconds)))
    if rest == 0:
        return "0s"
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        amount, rest = divmod(rest, size)
        if amount:
            parts.append(f"{amount}{unit}")
    return sign + " ".join(parts)


def format_offset(seconds: float) -> str:
    """Format a plan-relative time as "T+1d 2h" / "T-30m"."""
    if seconds == math.inf:
        return "never"
    if seconds == -math.inf:
        return "before the plan"
    if seconds == 0:
        return "T+0"
    sign = "+" if seconds > 0 else "-"
    return f"T{sign}{format_duration(abs(seconds))}"


def parse_start(value) -> datetime | None:
    """Parse an optional absolute plan start time (ISO 8601, naive values are UTC)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def format_time(seconds: float, start: datetime | None) -> str:
    """Plan-relative time, with the absolute UTC time appended when the plan has a start."""
    relative = format_offset(seconds)
    if start is None or math.isinf(seconds):
        return relative
    moment = start + timedelta(seconds=seconds)
    return f"{relative} ({moment.strftime('%a %d %b %H:%M UTC')})"

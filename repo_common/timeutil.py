"""UTC timestamps in one canonical text form (``2026-11-16T12:00:00Z``)."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Current time in UTC, whole seconds."""
    return datetime.now(UTC).replace(microsecond=0)


def format_utc(value: datetime) -> str:
    """Render ``value`` as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime:
    """Parse an ISO 8601 timestamp with a timezone; naive values are rejected."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp without timezone: {value!r}")
    return parsed.astimezone(UTC)


def parse_optional_utc(value: str | None) -> datetime | None:
    """Like :func:`parse_utc`, but ``None`` and ``""`` stay ``None``."""
    return parse_utc(value) if value else None

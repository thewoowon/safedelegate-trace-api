"""Datetime helpers.

SQLite does not persist timezone info, so datetimes loaded from the DB come back naive.
``ensure_utc`` coerces any datetime to timezone-aware UTC so comparisons against
``datetime.now(UTC)`` never mix naive and aware values.
"""

from __future__ import annotations

from datetime import UTC, datetime


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime (assuming UTC if naive)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)

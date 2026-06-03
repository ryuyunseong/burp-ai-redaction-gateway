from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import SanitizedEvent


def write_audit_db(path: Path, events: list[SanitizedEvent]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_map (
                evidence_id TEXT PRIMARY KEY,
                raw_reference TEXT NOT NULL,
                raw_values_included INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS redaction_counts (
                evidence_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (evidence_id, kind)
            )
            """
        )
        connection.execute("DELETE FROM evidence_map")
        connection.execute("DELETE FROM redaction_counts")
        for event in events:
            connection.execute(
                "INSERT INTO evidence_map VALUES (?, ?, ?)",
                (event.evidence_id, event.raw_reference, int(event.raw_values_included)),
            )
            for kind, count in event.redaction["counts"].items():
                connection.execute(
                    "INSERT INTO redaction_counts VALUES (?, ?, ?)",
                    (event.evidence_id, kind, int(count)),
                )
        connection.commit()
    finally:
        connection.close()

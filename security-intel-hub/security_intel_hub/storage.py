from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from security_intel_hub.models import IntelItem


RankedItem = tuple[int, IntelItem]


class SQLiteStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS intel_items (
                    dedupe_key TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    url TEXT NOT NULL,
                    author TEXT NOT NULL,
                    published_at TEXT,
                    score INTEGER NOT NULL DEFAULT 0,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_intel_items_source
                    ON intel_items(source, source_id);

                CREATE INDEX IF NOT EXISTS idx_intel_items_score
                    ON intel_items(score DESC, published_at DESC);

                CREATE TABLE IF NOT EXISTS push_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedupe_key TEXT NOT NULL,
                    notifier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    pushed_at TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(dedupe_key) REFERENCES intel_items(dedupe_key)
                );

                CREATE INDEX IF NOT EXISTS idx_push_events_lookup
                    ON push_events(dedupe_key, notifier, status);

                CREATE TABLE IF NOT EXISTS collector_state (
                    collector TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def upsert_ranked_items(self, ranked_items: list[RankedItem]) -> set[str]:
        now = _utc_now()
        new_keys: set[str] = set()
        with self._connect() as connection:
            for score, item in ranked_items:
                exists = connection.execute(
                    "SELECT 1 FROM intel_items WHERE dedupe_key = ?",
                    (item.dedupe_key,),
                ).fetchone()
                if exists is None:
                    new_keys.add(item.dedupe_key)

                connection.execute(
                    """
                    INSERT INTO intel_items (
                        dedupe_key, source, source_id, title, body, url, author,
                        published_at, score, first_seen_at, last_seen_at, raw_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(dedupe_key) DO UPDATE SET
                        title = excluded.title,
                        body = excluded.body,
                        url = excluded.url,
                        author = excluded.author,
                        published_at = COALESCE(excluded.published_at, intel_items.published_at),
                        score = excluded.score,
                        last_seen_at = excluded.last_seen_at,
                        raw_json = excluded.raw_json
                    """,
                    (
                        item.dedupe_key,
                        item.source,
                        item.source_id,
                        item.title,
                        item.body,
                        item.url,
                        item.author,
                        _format_datetime(item.published_at),
                        score,
                        now,
                        now,
                        json.dumps(item.raw, ensure_ascii=False, default=str),
                    ),
                )
        return new_keys

    def unpushed_for_notifier(self, ranked_items: list[RankedItem], notifier: str) -> list[RankedItem]:
        with self._connect() as connection:
            return [
                ranked_item
                for ranked_item in ranked_items
                if not _has_successful_push(connection, ranked_item[1].dedupe_key, notifier)
            ]

    def unpushed_for_any_notifier(self, ranked_items: list[RankedItem], notifiers: list[str]) -> list[RankedItem]:
        if not notifiers:
            return ranked_items
        with self._connect() as connection:
            return [
                ranked_item
                for ranked_item in ranked_items
                if any(not _has_successful_push(connection, ranked_item[1].dedupe_key, notifier) for notifier in notifiers)
            ]

    def record_push_events(
        self,
        ranked_items: list[RankedItem],
        *,
        notifier: str,
        status: str,
        error: str = "",
    ) -> None:
        now = _utc_now()
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO push_events (dedupe_key, notifier, status, title, pushed_at, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (item.dedupe_key, notifier, status, item.title, now, error)
                    for _, item in ranked_items
                ],
            )

    def get_collector_state(self, collector: str) -> dict[str, object]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state_json FROM collector_state WHERE collector = ?",
                (collector,),
            ).fetchone()
        return json.loads(row["state_json"]) if row else {}

    def set_collector_state(self, collector: str, state: dict[str, object]) -> None:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO collector_state (collector, state_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(collector) DO UPDATE SET
                    state_json = excluded.state_json,
                    updated_at = excluded.updated_at
                """,
                (collector, json.dumps(state, ensure_ascii=False, default=str), now),
            )

    def stats(self) -> dict[str, int]:
        with self._connect() as connection:
            item_count = connection.execute("SELECT COUNT(*) FROM intel_items").fetchone()[0]
            success_count = connection.execute(
                "SELECT COUNT(*) FROM push_events WHERE status = 'success'"
            ).fetchone()[0]
            failed_count = connection.execute(
                "SELECT COUNT(*) FROM push_events WHERE status = 'failed'"
            ).fetchone()[0]
        return {
            "items": item_count,
            "push_success": success_count,
            "push_failed": failed_count,
        }

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection


def build_store(config: dict[str, object]) -> SQLiteStore | None:
    storage = config.get("storage")
    if not isinstance(storage, dict) or not storage.get("enabled", True):
        return None
    sqlite_path = storage.get("sqlite_path", "data/security_intel_hub.db")
    store = SQLiteStore(str(sqlite_path))
    store.initialize()
    return store


def _has_successful_push(connection: sqlite3.Connection, dedupe_key: str, notifier: str) -> bool:
    row = connection.execute(
        """
        SELECT 1 FROM push_events
        WHERE dedupe_key = ? AND notifier = ? AND status = 'success'
        LIMIT 1
        """,
        (dedupe_key, notifier),
    ).fetchone()
    return row is not None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()

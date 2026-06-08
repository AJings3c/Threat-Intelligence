from __future__ import annotations

from tempfile import TemporaryDirectory
from unittest import TestCase

from security_intel_hub.models import IntelItem
from security_intel_hub.storage import SQLiteStore


class SQLiteStoreTest(TestCase):
    def test_records_successful_push_and_filters_duplicates(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteStore(f"{temp_dir}/intel.db")
            store.initialize()
            ranked_items = [
                (
                    8,
                    IntelItem(
                        source="rss",
                        source_id="1",
                        title="CVE exploit",
                        body="",
                        url="https://example.com/cve",
                    ),
                )
            ]

            new_keys = store.upsert_ranked_items(ranked_items)

            self.assertEqual(len(new_keys), 1)
            self.assertEqual(len(store.unpushed_for_notifier(ranked_items, "telegram")), 1)

            store.record_push_events(ranked_items, notifier="telegram", status="success")

            self.assertEqual(store.unpushed_for_notifier(ranked_items, "telegram"), [])
            self.assertEqual(len(store.unpushed_for_notifier(ranked_items, "dingtalk")), 1)

    def test_upsert_returns_only_first_seen_items(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteStore(f"{temp_dir}/intel.db")
            store.initialize()
            ranked_items = [
                (
                    8,
                    IntelItem(
                        source="rss",
                        source_id="1",
                        title="CVE exploit",
                        body="",
                        url="https://example.com/cve",
                    ),
                )
            ]

            self.assertEqual(len(store.upsert_ranked_items(ranked_items)), 1)
            self.assertEqual(store.upsert_ranked_items(ranked_items), set())

    def test_collector_state_round_trips(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteStore(f"{temp_dir}/intel.db")
            store.initialize()

            store.set_collector_state("x", {"since_id": "123"})

            self.assertEqual(store.get_collector_state("x"), {"since_id": "123"})

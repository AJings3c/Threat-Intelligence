from __future__ import annotations

from datetime import datetime, timezone
from unittest import TestCase

from security_intel_hub.models import IntelItem
from security_intel_hub.pipeline import format_digest, rank_items, score_item


class PipelineTest(TestCase):
    def test_score_item_uses_security_keywords(self) -> None:
        item = IntelItem(
            source="x",
            source_id="1",
            title="CVE exploit PoC published",
            body="RCE impact confirmed",
            url="https://x.com/example/status/1",
        )

        score = score_item(item, keywords=["CVE", "exploit", "PoC", "RCE"])

        self.assertGreaterEqual(score, 10)

    def test_rank_items_deduplicates_by_url(self) -> None:
        first = IntelItem(source="rss", source_id="a", title="CVE", body="", url="https://example.com/a")
        duplicate = IntelItem(source="x", source_id="b", title="CVE", body="", url="https://example.com/a")

        ranked = rank_items([first, duplicate], keywords=["CVE"])

        self.assertEqual(len(ranked), 1)

    def test_format_digest_contains_title_and_source(self) -> None:
        item = IntelItem(
            source="facebook",
            source_id="1",
            title="APT campaign update",
            body="",
            url="https://facebook.com/post",
            published_at=datetime(2026, 6, 8, tzinfo=timezone.utc),
        )

        digest = format_digest([(4, item)])

        self.assertIn("APT campaign update", digest)
        self.assertIn("facebook", digest)

    def test_format_digest_supports_custom_empty_message(self) -> None:
        digest = format_digest([], empty_message="暂无新的待推送安全情报。")

        self.assertIn("暂无新的待推送安全情报。", digest)

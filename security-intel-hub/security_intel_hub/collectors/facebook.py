from __future__ import annotations

from datetime import datetime

from security_intel_hub.http import request_json
from security_intel_hub.models import IntelItem


class FacebookPageCollector:
    name = "facebook"

    def __init__(
        self,
        *,
        access_token: str,
        page_ids: list[str],
        graph_version: str = "v23.0",
        limit: int = 25,
        api_base: str = "https://graph.facebook.com",
    ) -> None:
        self.access_token = access_token
        self.page_ids = page_ids
        self.graph_version = graph_version.strip("/")
        self.limit = max(1, min(limit, 100))
        self.api_base = api_base.rstrip("/")

    def collect(self) -> list[IntelItem]:
        if not self.access_token or not self.page_ids:
            return []

        items: list[IntelItem] = []
        for page_id in self.page_ids:
            response = request_json(
                "GET",
                f"{self.api_base}/{self.graph_version}/{page_id}/posts",
                params={
                    "fields": "id,message,created_time,permalink_url,from",
                    "limit": self.limit,
                    "access_token": self.access_token,
                },
            )
            for post in response.get("data", []):
                message = post.get("message", "").strip()
                if not message:
                    continue
                author = (post.get("from") or {}).get("name", page_id)
                items.append(
                    IntelItem(
                        source=self.name,
                        source_id=post["id"],
                        title=_headline(message),
                        body=message,
                        url=post.get("permalink_url", ""),
                        author=author,
                        published_at=_parse_datetime(post.get("created_time")),
                        raw=post,
                    )
                )
        return items


def _headline(text: str, length: int = 96) -> str:
    text = " ".join(text.split())
    return text if len(text) <= length else f"{text[: length - 1]}..."


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

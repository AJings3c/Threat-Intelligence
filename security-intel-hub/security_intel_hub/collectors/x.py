from __future__ import annotations

from datetime import datetime

from security_intel_hub.http import request_json
from security_intel_hub.models import IntelItem


class XRecentSearchCollector:
    name = "x"

    def __init__(
        self,
        *,
        bearer_token: str,
        query: str,
        max_results: int = 25,
        api_base: str = "https://api.x.com/2",
    ) -> None:
        self.bearer_token = bearer_token
        self.query = query
        self.max_results = max(10, min(max_results, 100))
        self.api_base = api_base.rstrip("/")

    def collect(self) -> list[IntelItem]:
        if not self.bearer_token:
            return []

        response = request_json(
            "GET",
            f"{self.api_base}/tweets/search/recent",
            headers={"Authorization": f"Bearer {self.bearer_token}"},
            params={
                "query": self.query,
                "max_results": self.max_results,
                "tweet.fields": "created_at,author_id,public_metrics,entities",
                "expansions": "author_id",
                "user.fields": "username,name",
            },
        )

        users = {
            user["id"]: user
            for user in response.get("includes", {}).get("users", [])
            if "id" in user
        }
        items: list[IntelItem] = []
        for tweet in response.get("data", []):
            author = users.get(tweet.get("author_id", ""), {})
            username = author.get("username", "")
            url = f"https://x.com/{username}/status/{tweet['id']}" if username else ""
            text = tweet.get("text", "").strip()
            items.append(
                IntelItem(
                    source=self.name,
                    source_id=tweet["id"],
                    title=_headline(text),
                    body=text,
                    url=url,
                    author=username or tweet.get("author_id", ""),
                    published_at=_parse_datetime(tweet.get("created_at")),
                    raw=tweet,
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

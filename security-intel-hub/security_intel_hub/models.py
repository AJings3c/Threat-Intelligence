from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class IntelItem:
    source: str
    source_id: str
    title: str
    body: str
    url: str
    author: str = ""
    published_at: datetime | None = None
    tags: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def dedupe_key(self) -> str:
        if self.url:
            return self.url.strip().lower()
        return f"{self.source}:{self.source_id}".lower()

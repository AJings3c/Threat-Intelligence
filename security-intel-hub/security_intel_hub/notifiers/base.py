from __future__ import annotations

from typing import Protocol


class Notifier(Protocol):
    name: str

    def notify(self, title: str, text: str) -> None:
        ...

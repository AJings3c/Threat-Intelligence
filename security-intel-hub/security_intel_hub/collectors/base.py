from __future__ import annotations

from typing import Protocol

from security_intel_hub.models import IntelItem


class Collector(Protocol):
    name: str

    def collect(self) -> list[IntelItem]:
        ...

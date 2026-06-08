from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from security_intel_hub.collectors import FacebookPageCollector, RssCollector, XRecentSearchCollector
from security_intel_hub.collectors.base import Collector
from security_intel_hub.http import HttpError
from security_intel_hub.models import IntelItem
from security_intel_hub.notifiers import DingTalkNotifier, TelegramNotifier
from security_intel_hub.notifiers.base import Notifier


DEFAULT_WEIGHTS = {
    "0day": 8,
    "zero-day": 8,
    "exploit": 7,
    "rce": 7,
    "cve": 6,
    "poc": 5,
    "ransomware": 5,
    "apt": 4,
    "ioc": 4,
    "breach": 4,
    "kev": 4,
    "phishing": 3,
    "malware": 3,
}


def build_collectors(config: dict[str, Any]) -> list[Collector]:
    collector_config = config.get("collectors", {})
    collectors: list[Collector] = []

    x_config = collector_config.get("x", {})
    if x_config.get("enabled"):
        collectors.append(
            XRecentSearchCollector(
                bearer_token=x_config.get("bearer_token", ""),
                query=x_config.get("query", ""),
                max_results=x_config.get("max_results", 25),
                api_base=x_config.get("api_base", "https://api.x.com/2"),
            )
        )

    facebook_config = collector_config.get("facebook", {})
    if facebook_config.get("enabled"):
        collectors.append(
            FacebookPageCollector(
                access_token=facebook_config.get("access_token", ""),
                page_ids=facebook_config.get("page_ids", []),
                graph_version=facebook_config.get("graph_version", "v23.0"),
                limit=facebook_config.get("limit", 25),
                api_base=facebook_config.get("api_base", "https://graph.facebook.com"),
            )
        )

    rss_config = collector_config.get("rss", {})
    if rss_config.get("enabled"):
        collectors.append(
            RssCollector(
                feeds=rss_config.get("feeds", []),
                limit_per_feed=rss_config.get("limit_per_feed", 20),
            )
        )

    return collectors


def build_notifiers(config: dict[str, Any]) -> list[Notifier]:
    notifier_config = config.get("notifiers", {})
    notifiers: list[Notifier] = []

    telegram_config = notifier_config.get("telegram", {})
    if telegram_config.get("enabled"):
        notifiers.append(
            TelegramNotifier(
                bot_token=telegram_config.get("bot_token", ""),
                chat_id=telegram_config.get("chat_id", ""),
                api_base=telegram_config.get("api_base", "https://api.telegram.org"),
            )
        )

    dingtalk_config = notifier_config.get("dingtalk", {})
    if dingtalk_config.get("enabled"):
        notifiers.append(
            DingTalkNotifier(
                webhook=dingtalk_config.get("webhook", ""),
                secret=dingtalk_config.get("secret", ""),
            )
        )

    return notifiers


def collect_all(collectors: list[Collector]) -> tuple[list[IntelItem], list[str]]:
    items: list[IntelItem] = []
    errors: list[str] = []
    for collector in collectors:
        try:
            items.extend(collector.collect())
        except HttpError as exc:
            errors.append(f"{collector.name}: {exc}; body={exc.body[:300]}")
        except Exception as exc:  # noqa: BLE001 - pipeline should keep other sources alive.
            errors.append(f"{collector.name}: {type(exc).__name__}: {exc}")
    return items, errors


def rank_items(
    items: list[IntelItem],
    *,
    keywords: list[str],
    weights: dict[str, int] | None = None,
    max_items: int = 25,
) -> list[tuple[int, IntelItem]]:
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    deduped: dict[str, IntelItem] = {}
    for item in items:
        deduped.setdefault(item.dedupe_key, item)

    ranked = [(score_item(item, keywords=keywords, weights=weights), item) for item in deduped.values()]
    ranked = [entry for entry in ranked if entry[0] > 0]
    ranked.sort(key=lambda entry: (entry[0], _sort_datetime(entry[1].published_at)), reverse=True)
    return ranked[:max_items]


def score_item(item: IntelItem, *, keywords: list[str], weights: dict[str, int] | None = None) -> int:
    weights = weights or DEFAULT_WEIGHTS
    text = f"{item.title}\n{item.body}".lower()
    score = 0
    for keyword in keywords:
        keyword_lower = keyword.lower()
        if keyword_lower in text:
            score += weights.get(keyword_lower, 2)

    if item.source == "x":
        metrics = item.raw.get("public_metrics") or {}
        score += min(15, int(math.log1p(metrics.get("retweet_count", 0)) * 2))
        score += min(10, int(math.log1p(metrics.get("like_count", 0))))

    return score


def format_digest(
    ranked_items: list[tuple[int, IntelItem]],
    *,
    generated_at: datetime | None = None,
    empty_message: str = "暂无命中安全情报。",
) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    if not ranked_items:
        return f"生成时间: {generated_at.isoformat()}\n\n{empty_message}"

    lines = [f"生成时间: {generated_at.isoformat()}"]
    for index, (score, item) in enumerate(ranked_items, start=1):
        when = item.published_at.isoformat() if item.published_at else "unknown time"
        author = f" / {item.author}" if item.author else ""
        lines.extend(
            [
                "",
                f"{index}. [{score}] {item.title}",
                f"   来源: {item.source}{author} / {when}",
                f"   链接: {item.url or 'N/A'}",
            ]
        )
    return "\n".join(lines)


def notify_all(notifiers: list[Notifier], title: str, text: str) -> list[str]:
    errors: list[str] = []
    for notifier in notifiers:
        try:
            notifier.notify(title, text)
        except HttpError as exc:
            errors.append(f"{notifier.name}: {exc}; body={exc.body[:300]}")
        except Exception as exc:  # noqa: BLE001 - one channel should not block the rest.
            errors.append(f"{notifier.name}: {type(exc).__name__}: {exc}")
    return errors


def _sort_datetime(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value

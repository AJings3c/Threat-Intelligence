from __future__ import annotations

import email.utils
import ssl
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from security_intel_hub.models import IntelItem


class RssCollector:
    name = "rss"

    def __init__(self, *, feeds: list[str], limit_per_feed: int = 20, timeout: int = 20) -> None:
        self.feeds = feeds
        self.limit_per_feed = limit_per_feed
        self.timeout = timeout

    def collect(self) -> list[IntelItem]:
        items: list[IntelItem] = []
        for feed_url in self.feeds:
            with urllib.request.urlopen(feed_url, timeout=self.timeout, context=_ssl_context()) as response:
                content = response.read()
            root = ET.fromstring(content)
            items.extend(self._parse(feed_url, root)[: self.limit_per_feed])
        return items

    def _parse(self, feed_url: str, root: ET.Element) -> list[IntelItem]:
        if root.tag.endswith("feed"):
            return self._parse_atom(feed_url, root)
        return self._parse_rss(feed_url, root)

    def _parse_rss(self, feed_url: str, root: ET.Element) -> list[IntelItem]:
        items: list[IntelItem] = []
        for node in root.findall(".//item"):
            title = _text(node, "title")
            link = _text(node, "link")
            body = _text(node, "description")
            guid = _text(node, "guid") or link or title
            items.append(
                IntelItem(
                    source=self.name,
                    source_id=guid,
                    title=title or _headline(body),
                    body=body or title,
                    url=link,
                    author=_text(node, "author"),
                    published_at=_parse_rfc2822(_text(node, "pubDate")),
                    raw={"feed": feed_url},
                )
            )
        return items

    def _parse_atom(self, feed_url: str, root: ET.Element) -> list[IntelItem]:
        namespace = {"atom": "http://www.w3.org/2005/Atom"}
        items: list[IntelItem] = []
        for entry in root.findall("atom:entry", namespace):
            title = _text_ns(entry, "atom:title", namespace)
            body = _text_ns(entry, "atom:summary", namespace) or _text_ns(entry, "atom:content", namespace)
            link = _atom_link(entry, namespace)
            source_id = _text_ns(entry, "atom:id", namespace) or link or title
            items.append(
                IntelItem(
                    source=self.name,
                    source_id=source_id,
                    title=title or _headline(body),
                    body=body or title,
                    url=link,
                    author=_text_ns(entry, "atom:author/atom:name", namespace),
                    published_at=_parse_iso(_text_ns(entry, "atom:updated", namespace)),
                    raw={"feed": feed_url},
                )
            )
        return items


def _text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    return (child.text or "").strip() if child is not None else ""


def _text_ns(node: ET.Element, tag: str, namespace: dict[str, str]) -> str:
    child = node.find(tag, namespace)
    return (child.text or "").strip() if child is not None else ""


def _atom_link(node: ET.Element, namespace: dict[str, str]) -> str:
    for link in node.findall("atom:link", namespace):
        if link.attrib.get("rel", "alternate") == "alternate" and link.attrib.get("href"):
            return link.attrib["href"]
    return ""


def _headline(text: str, length: int = 96) -> str:
    text = " ".join(text.split())
    return text if len(text) <= length else f"{text[: length - 1]}..."


def _parse_rfc2822(value: str) -> datetime | None:
    if not value:
        return None
    parsed = email.utils.parsedate_to_datetime(value)
    return parsed


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()

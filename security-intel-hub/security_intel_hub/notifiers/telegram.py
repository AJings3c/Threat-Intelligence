from __future__ import annotations

from security_intel_hub.http import request_json


class TelegramNotifier:
    name = "telegram"

    def __init__(self, *, bot_token: str, chat_id: str, api_base: str = "https://api.telegram.org") -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base = api_base.rstrip("/")

    def notify(self, title: str, text: str) -> None:
        if not self.bot_token or not self.chat_id:
            return

        for chunk in _chunks(f"{title}\n\n{text}", 3900):
            request_json(
                "POST",
                f"{self.api_base}/bot{self.bot_token}/sendMessage",
                json_body={
                    "chat_id": self.chat_id,
                    "text": chunk,
                    "disable_web_page_preview": True,
                },
            )


def _chunks(text: str, limit: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for line in text.splitlines():
        if len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks

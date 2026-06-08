from __future__ import annotations

import base64
import hashlib
import hmac
import time
import urllib.parse

from security_intel_hub.http import request_json


class DingTalkNotifier:
    name = "dingtalk"

    def __init__(self, *, webhook: str, secret: str = "") -> None:
        self.webhook = webhook
        self.secret = secret

    def notify(self, title: str, text: str) -> None:
        if not self.webhook:
            return

        request_json(
            "POST",
            self._signed_webhook(),
            json_body={
                "msgtype": "markdown",
                "markdown": {
                    "title": title,
                    "text": f"### {title}\n\n{text}",
                },
            },
        )

    def _signed_webhook(self) -> str:
        if not self.secret:
            return self.webhook

        timestamp = str(round(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{self.secret}".encode("utf-8")
        digest = hmac.new(self.secret.encode("utf-8"), string_to_sign, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(digest))
        separator = "&" if "?" in self.webhook else "?"
        return f"{self.webhook}{separator}timestamp={timestamp}&sign={sign}"

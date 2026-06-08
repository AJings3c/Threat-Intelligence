from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class HttpError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    if params:
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{query}"

    body = None
    request_headers = dict(headers or {})
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")

    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise HttpError(f"HTTP {exc.code} for {url}", status=exc.code, body=payload) from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"Network error for {url}: {exc.reason}") from exc

    if not payload:
        return {}
    return json.loads(payload)

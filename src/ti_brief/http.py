"""Bounded HTTP with TLS verification, no redirects, and redacted failures."""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class RemoteError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Http:
    def __init__(self, timeout=30, max_bytes=8_000_000, retries=2):
        self.timeout, self.max_bytes, self.retries = timeout, max_bytes, retries
        self.opener = build_opener(NoRedirect)

    def request(self, url, payload=None, headers=None, method=None):
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("HTTP(S) URL without embedded credentials required")
        body = None if payload is None else json.dumps(payload).encode()
        request_headers = {"User-Agent": "ti-brief/0.1 (+defensive lab)", "Accept": "application/json"}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        req = Request(url, data=body, headers=request_headers, method=method)
        # Retry reads only. Mutations are reconciled by stable UUID on next run.
        attempts = self.retries + 1 if req.get_method() == "GET" else 1
        for attempt in range(attempts):
            try:
                with self.opener.open(req, timeout=self.timeout) as response:
                    data = response.read(self.max_bytes + 1)
                    if len(data) > self.max_bytes:
                        raise RemoteError("Response exceeds configured size limit")
                    return data.decode("utf-8-sig")
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                retryable = not isinstance(exc, HTTPError) or exc.code in {429, 500, 502, 503, 504}
                status = exc.code if isinstance(exc, HTTPError) else "connection/timeout"
                if isinstance(exc, HTTPError):
                    exc.close()
                if attempt + 1 == attempts or not retryable:
                    # Never echo response bodies, URL query strings, tokens or exception text.
                    raise RemoteError(f"HTTP {status} from {parts.hostname}") from None
                time.sleep(min(2 ** attempt, 4))

    def json(self, url, payload=None, headers=None, method=None):
        try:
            return json.loads(self.request(url, payload, headers, method))
        except (ValueError, UnicodeError):
            raise RemoteError("Remote response was not valid JSON") from None

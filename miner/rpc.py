"""Minimal JSON-RPC client for bitcoind, using only the standard library."""

import base64
import json
import urllib.error
import urllib.request
from pathlib import Path


class RPCError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (code {code})")
        self.code = code


class BitcoinRPC:
    def __init__(self, url: str, user: str, password: str, timeout: float = 60):
        self.url = url
        self.timeout = timeout
        credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._headers = {"Authorization": f"Basic {credentials}", "Content-Type": "application/json"}

    @classmethod
    def from_cookie(cls, url: str, cookie_file: Path) -> "BitcoinRPC":
        """Authenticate with the cookie file bitcoind writes to its datadir on startup."""
        user, password = cookie_file.read_text().strip().split(":", 1)
        return cls(url, user, password)

    def call(self, method: str, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": params})
        request = urllib.request.Request(self.url, data=body.encode(), headers=self._headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                reply = json.load(response)
        except urllib.error.HTTPError as e:
            # bitcoind reports RPC errors as HTTP 4xx/5xx with a JSON body.
            # Auth failures (401) come back with no body at all.
            error_body = e.read()
            if not error_body:
                raise RPCError(e.code, f"HTTP {e.code} {e.reason}") from None
            reply = json.loads(error_body)
        if reply.get("error"):
            raise RPCError(reply["error"]["code"], reply["error"]["message"])
        return reply.get("result")

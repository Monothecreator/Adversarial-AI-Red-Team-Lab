from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, status


class RateLimiter:
    """Small fixed-window limiter for the local lab process."""

    def __init__(self, limit: int | None = None, window_seconds: int = 60):
        self.limit = limit or int(os.getenv("RED_TEAM_RATE_LIMIT", "30"))
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            requests = self._requests[client_id]
            while requests and now - requests[0] >= self.window_seconds:
                requests.popleft()
            if len(requests) >= self.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded for this client.",
                    headers={"Retry-After": str(self.window_seconds)},
                )
            requests.append(now)


def client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_api_key(
    request: Request,
    api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    expected = os.getenv("RED_TEAM_API_KEY", "local-dev-key")
    if not api_key or api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid X-API-Key header is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return client_id(request)

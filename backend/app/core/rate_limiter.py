"""
AegisSOC In-Memory Sliding-Window Rate Limiter
Defends against brute-force attacks, credential stuffing, and API resource exhaustion.
"""

from collections import defaultdict
from datetime import datetime, timezone
import threading
import time
from typing import Dict, List, Optional, Tuple
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter per client IP / key."""

    def __init__(self):
        # Map: rate_key -> list of timestamp floats
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int = 60
    ) -> Tuple[bool, int, int]:
        """
        Checks whether a request with 'key' is permitted under the rate limit.
        Returns (is_allowed, remaining_requests, retry_after_seconds).
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests[key]
            # Prune timestamps older than cutoff
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            self._requests[key] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                oldest_timestamp = valid_timestamps[0]
                retry_after = max(1, int(oldest_timestamp + window_seconds - now))
                remaining = 0
                return False, remaining, retry_after

            # Record this request
            self._requests[key].append(now)
            remaining = max_requests - len(self._requests[key])
            return True, remaining, 0

    def clear(self):
        """Clears all tracked rate limit records (useful for testing)."""
        with self._lock:
            self._requests.clear()


# Global rate limiter instance
limiter = SlidingWindowRateLimiter()


def rate_limit(max_requests: int = 60, window_seconds: int = 60):
    """FastAPI dependency to rate limit specific endpoint routes by client IP."""
    async def dependency(request: Request):
        # Allow disabling rate limiting in test suite via request state or header
        if request.headers.get("X-Test-Bypass-Rate-Limit") == "true":
            return

        client_ip = request.client.host if request.client else "127.0.0.1"
        endpoint = request.url.path
        key = f"{client_ip}:{endpoint}"

        allowed, remaining, retry_after = limiter.is_allowed(
            key=key,
            max_requests=max_requests,
            window_seconds=window_seconds
        )

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(max_requests),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(retry_after)
                }
            )

    return dependency

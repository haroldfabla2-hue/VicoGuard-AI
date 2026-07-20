"""
VicoGuard AI — Rate Limiting Middleware
=======================================
Adds per-user, per-endpoint rate limiting using slowapi (FastAPI limiter).

Plans:
    - free:    10 scans/hour, 30 API calls/minute
    - pro:     100 scans/hour, 120 API calls/minute
    - team:    500 scans/hour, 300 API calls/minute
    - enterprise: unlimited scans, 1000 API calls/minute

Usage (in main.py):
    from api.rate_limiter import limiter, rate_limit_middleware

    # After app = FastAPI(...)
    app.state.limiter = limiter

    # On scan endpoints:
    @app.post("/api/v1/scan/repository")
    @limiter.limit("10/hour", key_func=get_user_key)
    async def scan_repository(request: ScanRequest, ...):
        ...

Install:
    pip install slowapi
"""

import os
from functools import wraps
from typing import Callable, Optional

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False
    RateLimitExceeded = Exception

# Default limits by plan
PLAN_LIMITS = {
    "free": {"scans_per_hour": 10, "api_per_minute": 30},
    "pro": {"scans_per_hour": 100, "api_per_minute": 120},
    "team": {"scans_per_hour": 500, "api_per_minute": 300},
    "enterprise": {"scans_per_hour": 99999, "api_per_minute": 1000},
}

DEFAULT_LIMITS = PLAN_LIMITS["free"]


def get_plan_limits(plan: str) -> dict:
    """Get rate limits for a given plan."""
    return PLAN_LIMITS.get(plan, DEFAULT_LIMITS)


if SLOWAPI_AVAILABLE:
    # Redis storage if available, else in-memory
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        from slowapi.wrappers import Limiter as RedisLimiter

        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=redis_url,
            default_limits=["200 per minute"],
            headers_enabled=True,
        )
    else:
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["200 per minute"],
            headers_enabled=True,
        )

    def setup_rate_limiting(app):
        """Configure rate limiting on a FastAPI app."""
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)

    def get_user_key(request) -> str:
        """Extract user ID from request for per-user rate limiting."""
        # Try cookie-based session
        token = request.cookies.get("vicoguard_session", "")
        if token:
            return f"user:{token[:16]}"
        # Fallback to IP
        return get_remote_address(request)

else:
    # Fallback: no rate limiting if slowapi not installed
    limiter = None

    def setup_rate_limiting(app):
        """No-op when slowapi is not available."""
        import logging

        logging.getLogger("vicoguard.ratelimit").warning(
            "slowapi not installed — rate limiting disabled. "
            "Install with: pip install slowapi"
        )

    def get_user_key(request) -> str:
        return "anonymous"

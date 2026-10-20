
from collections import defaultdict
from time import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="API Sentinel Local Practice Target",
    version="1.0.0",
    docs_url="/docs",
)

# Simple in-memory rate limiter for local testing.
requests_by_ip = defaultdict(list)
RATE_LIMIT = 30
WINDOW_SECONDS = 60


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    now = time()

    # Keep only requests made within the last 60 seconds.
    recent_requests = [
        timestamp
        for timestamp in requests_by_ip[client_ip]
        if now - timestamp < WINDOW_SECONDS
    ]
    requests_by_ip[client_ip] = recent_requests

    if len(recent_requests) >= RATE_LIMIT:
        response = JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
        )
        response.headers["Retry-After"] = str(WINDOW_SECONDS)
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        response.headers["X-RateLimit-Remaining"] = "0"
    else:
        requests_by_ip[client_ip].append(now)

        response = await call_next(request)

        remaining = max(
            0,
            RATE_LIMIT - len(requests_by_ip[client_ip]),
        )
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

    # Security headers.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    return response


@app.get("/")
def home():
    return {
        "service": "local-demo-target",
        "status": "running",
        "version": "v1",
    }


@app.get("/v1/profile")
def profile():
    return {
        "id": 1,
        "name": "Example User",
    }


@app.get("/v1/health")
def health():
    return {
        "status": "healthy",
    }

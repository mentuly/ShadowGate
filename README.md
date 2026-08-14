# Async Reverse Proxy with Security Controls

A secure reverse-proxy project built with Python, FastAPI, Redis, and Docker. It forwards requests to a configured backend while applying WAF checks, rate limiting, request anomaly scoring, and admin protection.

## Features

- HTTP and WebSocket proxying with SSRF protections
- strict backend allowlist for allowed destinations
- WAF inspection for path, query, body, and header payloads
- rate limiting with Redis-backed state
- anomaly detection for suspicious traffic patterns
- admin dashboard for runtime rule toggling
- request ID and structured logging for operations visibility
- Docker-based deployment with a non-root runtime user

## Architecture

- proxy service: handles inbound traffic and forwards to the configured backend
- admin service: exposes management endpoints and the admin UI
- Redis: stores rate-limit state, runtime overrides, and operational metadata
- config.yaml: runtime configuration for backend, allowlist, WAF, admin, and ML settings

## Quick start

### Prerequisites

- Python 3.11+
- Redis running locally or via Docker Compose
- Docker and Docker Compose (optional)

### Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export ADMIN_AUTH_TOKEN=your-strong-secret
export REDIS_URL=redis://localhost:6379/0
uvicorn proxy.app:app --host 0.0.0.0 --port 8000
```

Then access:

- proxy: http://localhost:8000
- admin UI: http://localhost:8080

### Docker Compose

```bash
cp .env.example .env
# fill ADMIN_AUTH_TOKEN in .env
docker compose --env-file .env up --build
```

## Configuration

The project loads settings from config.yaml and supports environment overrides such as:

- PROXY_TARGET / TARGET_BACKEND
- REDIS_URL
- ADMIN_AUTH_TOKEN
- SSRF_ALLOWLIST
- WAF_ENABLED
- RATE_LIMIT_ENABLED
- ML_ENABLED
- LOG_LEVEL

See config.yaml for the default runtime configuration.

## Security model

The project is designed to reduce common proxy and admin risks:

- rejects absolute URLs and double-slash SSRF patterns
- blocks external backend destinations unless explicitly allowed
- strips unsafe upstream headers and validates backend targets
- enforces admin authentication on protected routes
- adds CSRF validation for state-changing admin actions
- caps request body size to avoid oversized payload abuse
- records security events and request metadata for review

## Observability

The proxy emits structured logs and supports per-request IDs for operational tracing. The runtime metrics endpoint is available at:

- /metrics
- /health
- /livez
- /readyz

## Testing

```bash
pytest -q
```

The current regression suite covers:

- proxy forwarding
- WAF blocking
- SSRF bypass prevention
- admin auth checks
- browser-style admin cookie flow
- rate-limit handling
- anomaly scoring

## Notes

This project is intended as a hardened example of a reverse proxy with security controls and operational safeguards, not as a substitute for a full enterprise edge-gateway stack. It is suitable for local deployment, demos, and security-focused testing.

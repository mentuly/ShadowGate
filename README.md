# Async Reverse Proxy + WAF + Admin UI

This project implements an asynchronous HTTP reverse proxy with a static Web Application Firewall (WAF), rate limiting, IP reputation support, request feature logging, and a small admin UI.

## Services

- `proxy`: Async reverse proxy that forwards requests to a backend target.
- `admin`: Admin panel to view blocked IPs and enable/disable WAF rules.
- `redis`: Redis instance used for rate limiting, pub/sub, and reputation state.

## Run locally

1. Build dependencies:
   ```bash
   docker compose build
   ```

2. Start the stack:
   ```bash
   docker compose up
   ```

3. Open services:
   - Proxy: http://localhost:8000
   - Admin UI: http://localhost:8080

## Configuration

Edit `config.yaml` to change `target_backend`, WAF rules, and rate limiting settings.

## Notes

- The proxy uses streaming request/response handling to avoid buffering large bodies in memory.
- WAF rules are configurable and can be toggled without restarting the service.
- Redis is used for atomic rate limiting and IP reputation scoring.

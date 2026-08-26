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

### Unit & Integration Tests

Run the full test suite:

```bash
pytest -v
```

Run specific test categories:

```bash
# Unit/regression tests
pytest tests/test_proxy.py tests/test_admin_csrf.py -v

# E2E integration tests
pytest tests/test_integration_e2e.py -v

# Benchmark tests (with latency measurements)
pytest tests/test_benchmarks.py -v --benchmark-only
```

The test suite covers:

- **proxy forwarding** — HTTP request forwarding and routing
- **WAF blocking** — SQL injection, XSS, path traversal detection
- **SSRF bypass prevention** — URL validation and backend allowlist enforcement
- **admin auth checks** — authentication and CSRF token validation
- **rate-limit handling** — token bucket and suspicious score tracking
- **anomaly scoring** — ML-based request anomaly detection
- **E2E workflows** — complete user flows through proxy and admin
- **concurrent requests** — multi-threaded request handling
- **error handling** — malformed requests and backend failures

### Performance Benchmarks

Run benchmarks to measure latency and throughput:

```bash
# Run all benchmarks with detailed stats
pytest tests/test_benchmarks.py --benchmark-only -v

# Run specific benchmark
pytest tests/test_benchmarks.py::TestProxyBenchmarks::test_simple_get_request --benchmark-only

# Generate benchmark comparison report
pytest tests/test_benchmarks.py --benchmark-only --benchmark-save=baseline
pytest tests/test_benchmarks.py --benchmark-only --benchmark-compare=baseline
```

Benchmarks measure:

- **latency** (p50, p95, p99 percentiles)
- **throughput** (requests per second)
- **request sizes** (small, medium, large payloads)
- **header overhead** (many headers scenario)
- **WAF scanning time** (normalized request scanning)
- **rate limit check overhead**
- **response parsing time** (JSON and text)

### Load Testing with Locust

Load test the proxy under concurrent user traffic:

```bash
# 1. Start services
docker-compose up -d

# 2. Run load tests with web UI (visit http://localhost:8089)
locust -f locustfile.py --host=http://localhost:8000 --web

# Or run headless with predefined load profile
locust -f locustfile.py --host=http://localhost:8000 --headless -u 100 -r 10 -t 120s
```

Locust profiles:

| Scenario | Users | Hatch Rate | Duration | Purpose |
|----------|-------|-----------|----------|---------|
| **Baseline** | 100 | 10/s | 2m | Normal load testing |
| **Stress Test** | 1000 | 100/s | 1m | Find breaking point |
| **Endurance** | 500 | 50/s | 10m | Long-running stability |
| **High Traffic** | 200 | 20/s | 5m | Rapid request handling |
| **Data Upload** | 50 | 5/s | 5m | Payload handling |

Run specific scenario:

```bash
# Stress test
locust -f locustfile.py --host=http://localhost:8000 --headless \
  -u 1000 -r 100 -t 60s --csv=reports/stress_test

# High traffic with specific user class
locust -f locustfile.py --host=http://localhost:8000 \
  -u 200 -r 20 --locustfile-classes HighTrafficUser,ComplexScenarioUser
```

Metrics tracked:

- **Response time** (min, max, avg, median)
- **Request/error rates**
- **P95/P99 latency**
- **Throughput** (requests per second)
- **Failure distribution** (by endpoint)

Export results:

```bash
# CSV format (for analysis in Excel/Python)
locust -f locustfile.py --host=http://localhost:8000 --headless \
  -u 100 -r 10 -t 60s --csv=reports/load_test

# This creates: reports/load_test_stats.csv, load_test_stats_history.csv, load_test_failures.csv
```

### Test Structure

```
tests/
├── test_proxy.py              # Core proxy functionality
├── test_admin_csrf.py         # Admin auth & CSRF validation
├── test_admin_nonascii.py     # Unicode handling
├── test_security_dynamic.py   # Dynamic security features
├── test_integration_e2e.py    # End-to-end workflows (NEW)
├── test_benchmarks.py         # Latency & throughput benchmarks (NEW)
└── __pycache__/
locustfile.py                  # Load testing scenarios (NEW)
```

## Analytics & Monitoring

The proxy includes a comprehensive analytics system for monitoring traffic patterns, security events, and detecting anomalies.

### Admin Dashboard

Visit **http://localhost:8080** to access the analytics dashboard:

- **Live traffic metrics** — Total requests, blocked requests, WAF matches
- **Security overview** — Attack types, rate-limit blocks, anomaly count
- **Interactive charts** — Hourly traffic trends, top endpoints, top attackers
- **Data exports** — Download reports in CSV or PDF format
- **Auto-refresh** — Dashboard updates every 30 seconds

### Analytics API Endpoints

```bash
# Get comprehensive dashboard data
curl http://localhost:8080/api/analytics/dashboard

# Traffic statistics
curl "http://localhost:8080/api/analytics/traffic?hours=24"

# Top violated WAF rules
curl http://localhost:8080/api/analytics/waf-rules

# Top blocked IP addresses
curl http://localhost:8080/api/analytics/blocked-ips

# Hourly traffic time series
curl http://localhost:8080/api/analytics/hourly-traffic

# Detect anomalies (spike/dip in traffic)
curl "http://localhost:8080/api/analytics/anomalies?hours=24&threshold=2.0"

# Detailed report (JSON)
curl "http://localhost:8080/api/analytics/report?hours=24"

# Export as CSV
curl http://localhost:8080/api/analytics/export/csv > report.csv

# Export as PDF
curl http://localhost:8080/api/analytics/export/pdf > report.pdf
```

### Analytics Capabilities

The `TrafficAnalytics` class (in `proxy/analytics.py`) provides:

| Method | Purpose | Returns |
|--------|---------|---------|
| `load_events(hours)` | Load security events from JSONL | List of events |
| `get_traffic_stats(hours)` | Total/blocked/WAF counts | Dict with counts and rates |
| `get_top_waf_rules(limit)` | Rank WAF violations | List of rule:count pairs |
| `get_top_blocked_ips(limit)` | Rank blocked IPs | List of ip:count pairs |
| `get_hourly_traffic(hours)` | Aggregate traffic by hour | Time series data |
| `detect_anomalies(hours, threshold)` | Find traffic spikes/dips | List of anomalies |
| `get_detailed_report(hours)` | Comprehensive multi-metric report | Full summary dict |
| `export_to_csv(filepath, data)` | Write analytics to CSV file | Saved file path |

### Anomaly Detection

The system detects traffic anomalies using Z-score based analysis:

```python
# Detect anomalies with custom threshold
anomalies = analytics.detect_anomalies(hours=24, threshold=2.0)

# Each anomaly contains:
{
  'hour': '2024-08-25T14:00:00+00:00',
  'request_count': 250,
  'expected_count': 50,
  'z_score': 3.2,
  'anomaly_type': 'spike'  # or 'dip'
}
```

**Threshold guide:**
- **threshold=1.5** — Sensitive (catches minor variations)
- **threshold=2.0** — Standard (good for typical traffic patterns)
- **threshold=3.0** — Strict (only major anomalies)

### Analyzing Raw Logs

The proxy logs all events to JSONL files:

```bash
# View recent security events
tail -f logs/proxy-events.jsonl | jq 'select(.event=="blocked") | {timestamp, reason, source_ip}'

# Export events for time period to CSV
python3 -c "
from proxy.analytics import TrafficAnalytics
analytics = TrafficAnalytics()
data = analytics.get_detailed_report(hours=24)
analytics.export_to_csv('daily_report.csv', [data])
"

# Find requests from specific IP
jq 'select(.source_ip=="192.168.1.100")' logs/proxy-events.jsonl

# Analyze request sizes
jq '.request_size' logs/requests.jsonl | sort -n | tail -20
```

### Testing Analytics

Run analytics tests to verify functionality:

```bash
# Run all analytics tests
pytest tests/test_analytics.py -v

# Test specific analytics feature
pytest tests/test_analytics.py::TestTrafficAnalytics::test_get_traffic_stats -v

# Test anomaly detection
pytest tests/test_analytics.py::TestAnomalyDetection -v

# Test export formats
pytest tests/test_analytics.py::TestReportExport -v
```

## Notes

This project is intended as a hardened example of a reverse proxy with security controls and operational safeguards, not as a substitute for a full enterprise edge-gateway stack. It is suitable for local deployment, demos, and security-focused testing.

# Analytics & Monitoring Guide

Comprehensive documentation for the proxy's analytics and monitoring system.

## Table of Contents

1. [Dashboard Overview](#dashboard-overview)
2. [API Reference](#api-reference)
3. [Core Analytics Module](#core-analytics-module)
4. [Anomaly Detection](#anomaly-detection)
5. [Log Format](#log-format)
6. [Export Formats](#export-formats)
7. [Example Queries](#example-queries)
8. [Performance Considerations](#performance-considerations)

---

## Dashboard Overview

The admin dashboard at **http://localhost:8080** provides a real-time view of proxy traffic and security events.

### Dashboard Features

**Metrics Grid**
- Total requests processed
- Blocked requests (rate limit + WAF violations)
- WAF rule matches (security threats detected)
- Live block rate percentage

**Interactive Charts**
- **Hourly Traffic** — Line chart showing traffic volume over time
- **Top Endpoints** — Bar chart of most-requested paths
- **Top Attackers** — Bar chart of most-blocked IP addresses
- **WAF Rules** — Pie chart of violation types

**Data Tables**
- Recent WAF violations with timestamp and rule
- Recently blocked IPs with block count
- Security summary statistics

**Export Options**
- **CSV** — Tabular format for spreadsheet analysis
- **PDF** — Formatted report with charts and summary

### Auto-Refresh

Dashboard data refreshes automatically every 30 seconds via JavaScript polling.

```javascript
// Browser-side refresh pattern
setInterval(async () => {
    const response = await fetch('/api/analytics/dashboard');
    const data = await response.json();
    updateCharts(data);
}, 30000);
```

---

## API Reference

All analytics endpoints return JSON. Query parameters accept optional time windows (default: 24 hours).

### GET /api/analytics/dashboard

Comprehensive dashboard snapshot with all metrics and chart data.

**Parameters:**
- `hours` (optional, default=24) — Time window in hours

**Response:**
```json
{
  "total_requests": 5234,
  "blocked_requests": 128,
  "waf_matches": 89,
  "block_rate": 0.024,
  "top_waf_rules": [
    {"rule": "sql_injection", "count": 45},
    {"rule": "xss_payload", "count": 28}
  ],
  "top_blocked_ips": [
    {"ip": "192.168.1.100", "count": 32},
    {"ip": "10.0.0.50", "count": 15}
  ],
  "hourly_traffic": [
    {"hour": "2024-08-25T14:00:00+00:00", "count": 210},
    {"hour": "2024-08-25T15:00:00+00:00", "count": 195}
  ],
  "anomalies": []
}
```

### GET /api/analytics/traffic

Traffic statistics for the specified time window.

**Parameters:**
- `hours` (optional, default=24) — Time window in hours

**Response:**
```json
{
  "total_requests": 5234,
  "blocked_by_rate_limit": 32,
  "blocked_by_waf": 89,
  "blocked_by_other": 7,
  "allowed_requests": 5107,
  "block_rate": 0.024,
  "allow_rate": 0.976,
  "time_window_hours": 24,
  "start_time": "2024-08-24T16:30:00+00:00",
  "end_time": "2024-08-25T16:30:00+00:00"
}
```

### GET /api/analytics/waf-rules

Ranked list of most-violated WAF rules.

**Parameters:**
- `limit` (optional, default=10) — Number of rules to return
- `hours` (optional, default=24) — Time window in hours

**Response:**
```json
{
  "rules": [
    {"rule": "sql_injection", "count": 45, "percentage": 0.506},
    {"rule": "xss_payload", "count": 28, "percentage": 0.315},
    {"rule": "path_traversal", "count": 16, "percentage": 0.180}
  ],
  "total_violations": 89,
  "time_window_hours": 24
}
```

### GET /api/analytics/blocked-ips

Ranked list of most-blocked IP addresses.

**Parameters:**
- `limit` (optional, default=10) — Number of IPs to return
- `hours` (optional, default=24) — Time window in hours

**Response:**
```json
{
  "blocked_ips": [
    {"ip": "192.168.1.100", "count": 32, "percentage": 0.250},
    {"ip": "10.0.0.50", "count": 15, "percentage": 0.117},
    {"ip": "172.16.0.1", "count": 8, "percentage": 0.062}
  ],
  "total_blocks": 128,
  "unique_ips": 45,
  "time_window_hours": 24
}
```

### GET /api/analytics/hourly-traffic

Time-series traffic aggregated by hour.

**Parameters:**
- `hours` (optional, default=24) — Time window in hours

**Response:**
```json
{
  "hourly_data": [
    {
      "hour": "2024-08-25T14:00:00+00:00",
      "total_requests": 210,
      "allowed": 195,
      "blocked": 15,
      "requests_per_minute": 3.5
    },
    {
      "hour": "2024-08-25T15:00:00+00:00",
      "total_requests": 195,
      "allowed": 182,
      "blocked": 13,
      "requests_per_minute": 3.25
    }
  ],
  "total_requests": 5234,
  "average_rps": 3.2,
  "peak_rps": 5.8
}
```

### GET /api/analytics/anomalies

Detected traffic anomalies using Z-score analysis.

**Parameters:**
- `hours` (optional, default=24) — Time window in hours
- `threshold` (optional, default=2.0) — Z-score threshold for detection

**Response:**
```json
{
  "anomalies": [
    {
      "hour": "2024-08-25T14:00:00+00:00",
      "request_count": 250,
      "expected_count": 50,
      "z_score": 3.2,
      "anomaly_type": "spike",
      "deviation_percent": 400
    }
  ],
  "analysis": {
    "mean_rps": 50,
    "std_dev_rps": 12,
    "threshold": 2.0,
    "threshold_rps": 74,
    "anomalies_found": 1
  }
}
```

### GET /api/analytics/report

Detailed analytics report with all metrics.

**Parameters:**
- `hours` (optional, default=24) — Time window in hours

**Response:**
```json
{
  "report_generated_at": "2024-08-25T16:30:00+00:00",
  "time_window": {"start": "2024-08-24T16:30:00+00:00", "end": "2024-08-25T16:30:00+00:00"},
  "traffic_summary": { /* get_traffic_stats */ },
  "top_waf_rules": { /* get_top_waf_rules */ },
  "top_blocked_ips": { /* get_top_blocked_ips */ },
  "hourly_breakdown": { /* get_hourly_traffic */ },
  "anomalies": { /* detect_anomalies */ },
  "security_summary": {
    "total_security_events": 128,
    "waf_violations": 89,
    "rate_limit_blocks": 32,
    "ssrf_blocks": 7
  }
}
```

### GET /api/analytics/export/csv

Export analytics data as CSV file.

**Response:** Binary CSV file
- Filename: `analytics_report_<timestamp>.csv`
- Contains: Hourly traffic, top rules, top IPs, security summary

### GET /api/analytics/export/pdf

Export analytics report as PDF file.

**Response:** Binary PDF file
- Filename: `analytics_report_<timestamp>.pdf`
- Contains: Summary table, traffic statistics, charts, security events

---

## Core Analytics Module

The `TrafficAnalytics` class in `proxy/analytics.py` provides the analytics engine.

### Initialization

```python
from proxy.analytics import TrafficAnalytics

# Initialize with default log paths
analytics = TrafficAnalytics()

# Or specify custom paths
analytics = TrafficAnalytics(
    event_log_path='custom/path/events.jsonl',
    request_log_path='custom/path/requests.jsonl'
)
```

### Main Methods

#### load_events(hours=24)

Load security events from JSONL file within time window.

```python
events = analytics.load_events(hours=24)
# Returns: List[dict] with keys: event, timestamp, source_ip, reason, rule, etc.
```

#### get_traffic_stats(hours=24)

Calculate traffic statistics.

```python
stats = analytics.get_traffic_stats(hours=24)
# Returns: {
#   'total_requests': int,
#   'blocked_requests': int,
#   'waf_matches': int,
#   'block_rate': float,
#   'hours': int
# }
```

#### get_top_waf_rules(limit=10, hours=24)

Get most-violated WAF rules ranked by frequency.

```python
rules = analytics.get_top_waf_rules(limit=10, hours=24)
# Returns: [
#   {'rule': 'sql_injection', 'count': 45},
#   {'rule': 'xss_payload', 'count': 28},
#   ...
# ]
```

#### get_top_blocked_ips(limit=10, hours=24)

Get most-blocked IP addresses ranked by frequency.

```python
ips = analytics.get_top_blocked_ips(limit=10, hours=24)
# Returns: [
#   {'ip': '192.168.1.100', 'count': 32},
#   {'ip': '10.0.0.50', 'count': 15},
#   ...
# ]
```

#### get_hourly_traffic(hours=24)

Aggregate traffic by hour.

```python
hourly = analytics.get_hourly_traffic(hours=24)
# Returns: [
#   {
#     'hour': '2024-08-25T14:00:00+00:00',
#     'total_requests': 210,
#     'allowed': 195,
#     'blocked': 15,
#     'requests_per_minute': 3.5
#   },
#   ...
# ]
```

#### detect_anomalies(hours=24, threshold=2.0)

Detect traffic spikes and dips using Z-score analysis.

```python
anomalies = analytics.detect_anomalies(hours=24, threshold=2.0)
# Returns: [
#   {
#     'hour': '2024-08-25T14:00:00+00:00',
#     'request_count': 250,
#     'expected_count': 50,
#     'z_score': 3.2,
#     'anomaly_type': 'spike'
#   },
#   ...
# ]
```

**Threshold Examples:**
- `threshold=1.5` — Sensitive (catches ±1.5σ deviations)
- `threshold=2.0` — Standard (catches ±2σ deviations, ~95% confidence)
- `threshold=3.0` — Strict (catches ±3σ deviations, ~99.7% confidence)

#### get_detailed_report(hours=24)

Generate comprehensive multi-metric report.

```python
report = analytics.get_detailed_report(hours=24)
# Returns: Dict with all metrics combined
```

#### export_to_csv(filepath, data)

Write analytics data to CSV file.

```python
analytics.export_to_csv(
    filepath='report.csv',
    data=analytics.get_detailed_report(hours=24)
)
# Creates: report.csv with analytics data
```

---

## Anomaly Detection

### Algorithm: Z-Score Based Detection

The anomaly detection system uses statistical analysis to identify unusual traffic patterns.

### Step 1: Aggregate Traffic by Hour

```
Hour 1: 100 requests
Hour 2: 95 requests
Hour 3: 102 requests
...
Hour 24: 250 requests  ← Anomaly (spike)
```

### Step 2: Calculate Mean and Standard Deviation

```
Mean (μ) = 105 requests/hour
Std Dev (σ) = 15 requests/hour
```

### Step 3: Calculate Z-Score

```
Z = (observed - mean) / std_dev
Z = (250 - 105) / 15 = 9.67
```

### Step 4: Compare to Threshold

```
If |Z| > threshold → Anomaly detected

threshold=2.0  →  Z > 2.0 means anomaly
If Z > 0: spike (too many requests)
If Z < 0: dip (too few requests)
```

### Configuration

```python
# Sensitive detection (catches 1 in 6 variations)
analytics.detect_anomalies(threshold=1.5)

# Standard detection (catches 1 in 22 variations)
analytics.detect_anomalies(threshold=2.0)

# Strict detection (catches 1 in 370 variations)
analytics.detect_anomalies(threshold=3.0)
```

### When to Adjust

**Increase threshold if:**
- Many false positives (normal traffic flagged as anomaly)
- Expected traffic variations (e.g., business hours vs. night)
- Gradual load ramps (testing deployments)

**Decrease threshold if:**
- Missing real anomalies
- Need early warning on small deviations
- Production stability is critical

---

## Log Format

### Event Log (proxy-events.jsonl)

Each line is a JSON object representing a security event.

```json
{
  "event": "blocked",
  "timestamp": "2024-08-25T14:30:45+00:00",
  "source_ip": "192.168.1.100",
  "reason": "rate_limit",
  "details": {"current_score": 50, "threshold": 40}
}
```

**Event Types:**
- `"blocked"` — Request rejected (rate limit, WAF, SSRF)
- `"forwarded"` — Request sent to backend
- `"cached"` — Response from cache

**Reason Types:**
- `"rate_limit"` — Token bucket exhausted
- `"waf_violation"` — WAF rule matched
- `"ssrf_block"` — SSRF URL validation failed
- `"anomaly"` — Anomaly scoring threshold exceeded

### Request Log (requests.jsonl)

Detailed metrics for each request.

```json
{
  "timestamp": "2024-08-25T14:30:45+00:00",
  "method": "POST",
  "path": "/api/users",
  "query_string": "limit=10&offset=0",
  "request_size": 1024,
  "response_size": 2048,
  "status_code": 200,
  "latency_ms": 45.3,
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

---

## Export Formats

### CSV Format

Exported CSV contains:

```
timestamp,metric,value,unit
2024-08-25T14:00:00+00:00,total_requests,210,count
2024-08-25T14:00:00+00:00,allowed_requests,195,count
2024-08-25T14:00:00+00:00,blocked_requests,15,count
2024-08-25T14:00:00+00:00,requests_per_minute,3.5,rpm
...
rule,violations,percentage
sql_injection,45,50.6%
xss_payload,28,31.5%
...
ip_address,blocks,percentage
192.168.1.100,32,25.0%
10.0.0.50,15,11.7%
...
```

**Usage:**
```bash
# Download via API
curl http://localhost:8080/api/analytics/export/csv > report.csv

# Analyze in Python
import pandas as pd
df = pd.read_csv('report.csv')
df[df['metric'] == 'total_requests']
```

### PDF Format

Exported PDF contains:

- Title page with report date and time window
- Executive summary (total requests, blocks, rates)
- Key metrics table
- Traffic chart (hourly requests)
- Top rules table
- Top IPs table
- Anomalies section (if any detected)
- Security event summary

**Usage:**
```bash
# Download via API
curl http://localhost:8080/api/analytics/export/pdf > report.pdf

# Generated filename: analytics_report_<timestamp>.pdf
```

---

## Example Queries

### Find All Requests from Specific IP

```bash
# Via JSONL
jq 'select(.source_ip=="192.168.1.100")' logs/proxy-events.jsonl

# Count occurrences
jq 'select(.source_ip=="192.168.1.100")' logs/proxy-events.jsonl | wc -l

# Via API
curl "http://localhost:8080/api/analytics/blocked-ips?limit=1000" | jq '.blocked_ips[] | select(.ip=="192.168.1.100")'
```

### Analyze Request Sizes

```bash
# Find largest requests
jq '.request_size' logs/requests.jsonl | sort -rn | head -20

# Average request size
jq '.request_size' logs/requests.jsonl | awk '{sum+=$1} END {print sum/NR " bytes"}'

# Find requests over 1MB
jq 'select(.request_size > 1048576)' logs/requests.jsonl
```

### Monitor WAF Activity

```bash
# Real-time WAF violations
tail -f logs/proxy-events.jsonl | jq 'select(.reason=="waf_violation") | {timestamp, source_ip, details: .details.rule}'

# Top WAF rules for today
jq 'select(.reason=="waf_violation")' logs/proxy-events.jsonl | jq '.details.rule' | sort | uniq -c | sort -rn | head -10
```

### Detect Traffic Spikes

```bash
# Via API
curl "http://localhost:8080/api/analytics/anomalies?hours=24&threshold=2.0" | jq '.anomalies[] | select(.anomaly_type=="spike")'

# Via Python
from proxy.analytics import TrafficAnalytics
analytics = TrafficAnalytics()
anomalies = analytics.detect_anomalies(hours=24, threshold=2.0)
spikes = [a for a in anomalies if a['anomaly_type'] == 'spike']
for spike in spikes:
    print(f"{spike['hour']}: {spike['request_count']} requests (expected ~{spike['expected_count']})")
```

### Generate Daily Report

```bash
# Via API
curl "http://localhost:8080/api/analytics/report?hours=24" > daily_report.json

# Via Python Script
from proxy.analytics import TrafficAnalytics
import json
from datetime import datetime

analytics = TrafficAnalytics()
report = analytics.get_detailed_report(hours=24)

# Save JSON report
with open(f'report_{datetime.now().date()}.json', 'w') as f:
    json.dump(report, f, indent=2, default=str)

# Export CSV
analytics.export_to_csv(
    f'report_{datetime.now().date()}.csv',
    report
)

print("Report generated successfully")
```

---

## Performance Considerations

### Log File Size Management

JSONL log files grow over time. Implement rotation:

```bash
# In cron job: rotate logs daily
#!/bin/bash
cd /home/user/proxy/logs
timestamp=$(date +%Y%m%d_%H%M%S)
gzip -c proxy-events.jsonl > proxy-events_$timestamp.jsonl.gz
gzip -c requests.jsonl > requests_$timestamp.jsonl.gz
> proxy-events.jsonl  # Truncate
> requests.jsonl      # Truncate
```

### Query Performance

For large log files (>100MB), analytics queries may be slow.

**Optimization strategies:**
1. Query shorter time windows (e.g., last 7 days instead of 90)
2. Run analytical queries off-peak
3. Archive old logs (compress, move to separate storage)
4. Pre-compute hourly summaries during low traffic

```python
# Query last 7 days instead of full history
stats = analytics.get_traffic_stats(hours=7*24)  # 7 days
```

### Memory Usage

Large JSONL files are loaded entirely into memory. For multi-GB logs:

```python
# Option 1: Stream processing
import json
event_count = 0
with open('proxy-events.jsonl') as f:
    for line in f:
        event = json.loads(line)
        # Process one event at a time
        event_count += 1

# Option 2: Use smaller time windows
analytics.get_traffic_stats(hours=24)  # Last 24 hours only
```

### Recommended Archive Strategy

```
Current logs (last 7 days): proxy-events.jsonl, requests.jsonl
Weekly backups (4 weeks): logs/archive/week_1.tar.gz, week_2.tar.gz, ...
Monthly archives: logs/archive/month_01.tar.gz, month_02.tar.gz, ...
Retention: Keep 90 days of data online, archive rest
```

---

## Testing Analytics

Run the test suite to verify analytics functionality:

```bash
# All analytics tests
pytest tests/test_analytics.py -v

# Specific test class
pytest tests/test_analytics.py::TestTrafficAnalytics -v

# With output
pytest tests/test_analytics.py -v -s
```

**Test coverage includes:**
- ✅ Data loading from JSONL files
- ✅ Traffic statistics calculation
- ✅ Top rules and IPs ranking
- ✅ Hourly traffic aggregation
- ✅ Anomaly detection
- ✅ CSV and PDF export
- ✅ Edge cases (empty logs, malformed JSON)

---

## Troubleshooting

### Dashboard Shows No Data

1. Verify log files exist:
   ```bash
   ls -lh logs/proxy-events.jsonl logs/requests.jsonl
   ```

2. Check log format is valid JSONL:
   ```bash
   head -1 logs/proxy-events.jsonl | jq .
   ```

3. Verify timestamps are recent:
   ```bash
   tail -1 logs/proxy-events.jsonl | jq '.timestamp'
   ```

### Anomaly Detection Not Working

1. Check if enough data exists:
   - Need at least 3+ hours of data for meaningful analysis
   - Need variation in traffic (not flat line)

2. Adjust threshold:
   ```python
   # Lower threshold to catch more anomalies
   anomalies = analytics.detect_anomalies(threshold=1.5)
   ```

3. Debug anomaly calculation:
   ```python
   hourly = analytics.get_hourly_traffic()
   print(f"Hours with data: {len(hourly)}")
   print(f"Min: {min(h['total_requests'] for h in hourly)}")
   print(f"Max: {max(h['total_requests'] for h in hourly)}")
   ```

### PDF Export Fails

1. Check reportlab is installed:
   ```bash
   pip install reportlab
   ```

2. Check file permissions:
   ```bash
   touch /tmp/test_pdf.pdf  # Verify write access
   ```

3. Check PDF report generation manually:
   ```python
   from proxy.analytics import TrafficAnalytics
   analytics = TrafficAnalytics()
   # This will print any PDF generation errors
   ```

---

**Last Updated:** 2024-08-25
**Version:** 1.0

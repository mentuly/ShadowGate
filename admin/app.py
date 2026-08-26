import json
import logging
import os
import hmac
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from redis.asyncio import Redis

from proxy.config import ConfigManager
from proxy.model import train_model
from proxy.rate_limit import get_blocked_ips, get_rate_limit_stats, get_redis_client
from proxy.analytics import TrafficAnalytics

@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    await config_manager.initialize()
    try:
        global redis_client
        try:
            redis_client = get_redis_client(redis_url)
            await redis_client.ping()
        except Exception:
            redis_client = None
            logging.warning('Redis is unavailable, admin UI will show empty state.')
        yield
    finally:
        await config_manager.shutdown()
        if redis_client:
            await redis_client.close()


app = FastAPI(lifespan=lifespan)

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
config_file = os.getenv('CONFIG_FILE', 'config.yaml')
redis_client: Redis | None = None
config_manager = ConfigManager(config_file, redis_url=redis_url)
analytics = TrafficAnalytics()


def _get_expected_admin_token() -> str | None:
    return os.getenv('ADMIN_AUTH_TOKEN') or config_manager.config.admin.get('auth_token')


def _get_provided_admin_token(request: Request | WebSocket) -> str | None:
    headers = request.headers
    token = headers.get('x-admin-token')
    if token:
        return token
    auth_header = headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:].strip()
    cookie_token = request.cookies.get('admin_token') if not isinstance(request, WebSocket) else request.cookies.get('admin_token')
    if cookie_token:
        return cookie_token
    return None


def _get_provided_csrf_token(request: Request) -> str | None:
    # Only accept the CSRF token provided in the request header.
    # Falling back to the cookie here would make the double-submit protection a no-op.
    return request.headers.get('x-csrf-token')


def _constant_time_compare(a: object, b: object) -> bool:
    """Compare two values in constant time, handling str and bytes safely.

    HTTP headers may contain raw Latin-1 bytes decoded into Python `str`.
    Normalize both sides to `bytes` using Latin-1 so comparisons won't raise
    TypeError for non-ASCII header values and remain constant-time.
    """
    if isinstance(a, (bytes, bytearray)):
        a_bytes = bytes(a)
    else:
        a_bytes = str(a).encode('latin-1', errors='surrogateescape')

    if isinstance(b, (bytes, bytearray)):
        b_bytes = bytes(b)
    else:
        b_bytes = str(b).encode('latin-1', errors='surrogateescape')

    return hmac.compare_digest(a_bytes, b_bytes)


@app.middleware('http')
async def require_admin_auth(request: Request, call_next):
    # Respect `admin.enabled` flag from config
    if not config_manager.config.admin.get('enabled', True):
        return JSONResponse({'detail': 'Not found'}, status_code=404)

    expected_token = _get_expected_admin_token()
    if not expected_token:
        return JSONResponse({'detail': 'Admin authentication required'}, status_code=401)

    provided_token = _get_provided_admin_token(request)
    if not provided_token or not _constant_time_compare(provided_token, expected_token):
        return JSONResponse({'detail': 'Admin authentication required'}, status_code=401)

    if request.method != 'GET':
        csrf_token = _get_provided_csrf_token(request)
        cookie = request.cookies.get('admin_csrf')
        if not csrf_token or not cookie or not _constant_time_compare(csrf_token, cookie):
            return JSONResponse({'detail': 'Invalid CSRF token'}, status_code=403)

    response = await call_next(request)
    if request.url.path == '/' and request.method == 'GET':
        secure_flag = config_manager.config.admin.get('secure_cookies', True)
        # Ensure cookie values are safe for latin-1 encoding in Starlette internals.
        # Environment variables may contain raw bytes decoded with surrogateescape
        # (e.g. non-ASCII tokens). Convert back to bytes and decode with latin-1
        # so the resulting str can be encoded to latin-1 without surrogates.
        try:
            safe_token = expected_token.encode('latin-1', 'surrogateescape').decode('latin-1')
        except Exception:
            # Fallback: coerce to str — may still contain safe ASCII only
            safe_token = str(expected_token)

        response.set_cookie('admin_token', safe_token, httponly=True, samesite='lax', secure=secure_flag)
        response.set_cookie('admin_csrf', os.urandom(16).hex(), httponly=False, samesite='lax', secure=secure_flag)
    return response


@app.get('/')
async def index():
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy Analytics Dashboard</title>
  <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }
    .header h1 { font-size: 32px; margin-bottom: 10px; }
    .header p { opacity: 0.9; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .card h3 { margin-bottom: 15px; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
    .stat { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
    .stat:last-child { border-bottom: none; }
    .stat-label { color: #666; }
    .stat-value { font-weight: bold; color: #333; font-size: 18px; }
    .stat-value.danger { color: #e74c3c; }
    .stat-value.warning { color: #f39c12; }
    .stat-value.success { color: #27ae60; }
    .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px; }
    .chart-container h3 { margin-bottom: 20px; color: #333; }
    .button-group { display: flex; gap: 10px; margin-top: 15px; }
    button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; transition: background 0.3s; }
    button:hover { background: #764ba2; }
    button.secondary { background: #95a5a6; }
    button.secondary:hover { background: #7f8c8d; }
    .table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .table th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: bold; border-bottom: 2px solid #dee2e6; }
    .table td { padding: 12px; border-bottom: 1px solid #dee2e6; }
    .table tbody tr:hover { background: #f8f9fa; }
    .alert { padding: 15px; border-radius: 5px; margin-bottom: 15px; }
    .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
    .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔒 Proxy Analytics Dashboard</h1>
    <p>Real-time traffic analysis, security metrics, and anomaly detection</p>
  </div>
  
  <div class="grid">
    <div class="card">
      <h3>📊 Traffic Summary</h3>
      <div class="stat">
        <span class="stat-label">Total Requests</span>
        <span class="stat-value" id="total-requests">-</span>
      </div>
      <div class="stat">
        <span class="stat-label">Blocked Requests</span>
        <span class="stat-value danger" id="blocked-requests">-</span>
      </div>
      <div class="stat">
        <span class="stat-label">WAF Blocks</span>
        <span class="stat-value warning" id="waf-blocks">-</span>
      </div>
      <div class="stat">
        <span class="stat-label">Block Rate</span>
        <span class="stat-value danger" id="block-rate">-</span>
      </div>
    </div>

    <div class="card">
      <h3>🛡️ Security Status</h3>
      <div class="stat">
        <span class="stat-label">Total Events</span>
        <span class="stat-value" id="security-total">-</span>
      </div>
      <div class="stat">
        <span class="stat-label">WAF Events</span>
        <span class="stat-value warning" id="security-waf">-</span>
      </div>
      <div class="stat">
        <span class="stat-label">Rate Limit Events</span>
        <span class="stat-value warning" id="security-rate-limit">-</span>
      </div>
      <div class="stat">
        <span class="stat-label">SSRF Blocks</span>
        <span class="stat-value" id="security-ssrf">-</span>
      </div>
    </div>

    <div class="card">
      <h3>⚙️ Admin Controls</h3>
      <div class="button-group">
        <button onclick="refreshDashboard()">🔄 Refresh</button>
        <button class="secondary" onclick="exportCSV()">📥 Export CSV</button>
        <button class="secondary" onclick="exportPDF()">📄 Export PDF</button>
      </div>
      <div style="margin-top: 20px;">
        <h4 style="margin-bottom: 10px;">WAF Rules</h4>
        <div id="waf-rules-list"></div>
      </div>
    </div>
  </div>

  <div class="chart-container">
    <h3>📈 Hourly Traffic</h3>
    <div id="hourly-chart" style="height: 400px;"></div>
  </div>

  <div class="chart-container">
    <h3>🔴 Top WAF Rules</h3>
    <table class="table">
      <thead>
        <tr><th>Rule</th><th>Blocks</th></tr>
      </thead>
      <tbody id="waf-rules-table"></tbody>
    </table>
  </div>

  <div class="chart-container">
    <h3>⛔ Top Blocked IPs</h3>
    <table class="table">
      <thead>
        <tr><th>IP Address</th><th>Blocks</th></tr>
      </thead>
      <tbody id="blocked-ips-table"></tbody>
    </table>
  </div>

  <div class="chart-container">
    <h3>⚠️ Detected Anomalies</h3>
    <div id="anomalies-list"></div>
  </div>

  <div class="footer">
    <p>Last updated: <span id="last-updated">-</span></p>
  </div>

  <script>
    function getCookie(name) {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop().split(';').shift();
      return null;
    }

    function csrfHeaders() {
      const token = getCookie('admin_csrf');
      return token ? { 'X-CSRF-Token': token } : {};
    }

    async function fetchJson(path, options = {}) {
      const res = await fetch(path, {
        ...options,
        headers: {
          ...csrfHeaders(),
          ...(options.headers || {}),
        },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    }

    async function refreshDashboard() {
      try {
        const data = await fetchJson('/api/analytics/dashboard');
        
        // Traffic stats
        const traffic = data.traffic_stats;
        document.getElementById('total-requests').textContent = traffic.total_requests;
        document.getElementById('blocked-requests').textContent = traffic.blocked_requests;
        document.getElementById('waf-blocks').textContent = traffic.waf_blocks;
        document.getElementById('block-rate').textContent = traffic.block_rate + '%';
        
        // Security summary
        const security = data.security_summary;
        document.getElementById('security-total').textContent = security.total_events;
        document.getElementById('security-waf').textContent = security.waf_events;
        document.getElementById('security-rate-limit').textContent = security.rate_limit_events;
        document.getElementById('security-ssrf').textContent = security.ssrf_blocked;
        
        // Hourly traffic chart
        const hourly = data.hourly_traffic;
        if (hourly.length > 0) {
          const hours = hourly.map(h => h.hour.split(' ')[1]);
          const totals = hourly.map(h => h.total);
          const blocked = hourly.map(h => h.blocked);
          
          const trace1 = { x: hours, y: totals, type: 'scatter', mode: 'lines+markers', name: 'Total' };
          const trace2 = { x: hours, y: blocked, type: 'scatter', mode: 'lines+markers', name: 'Blocked' };
          Plotly.newPlot('hourly-chart', [trace1, trace2], { 
            responsive: true,
            margin: { l: 50, r: 50, t: 20, b: 50 },
          });
        }
        
        // WAF rules table
        const wafRules = data.top_waf_rules;
        const wafTable = document.getElementById('waf-rules-table');
        wafTable.innerHTML = '';
        for (const rule of wafRules) {
          wafTable.innerHTML += `<tr><td>${rule.rule}</td><td>${rule.count}</td></tr>`;
        }
        
        // Blocked IPs table
        const blockedIps = data.top_blocked_ips;
        const ipTable = document.getElementById('blocked-ips-table');
        ipTable.innerHTML = '';
        for (const ip of blockedIps) {
          ipTable.innerHTML += `<tr><td>${ip.ip}</td><td>${ip.count}</td></tr>`;
        }
        
        // Anomalies
        const anomalies = await fetchJson('/api/analytics/anomalies');
        const anomaliesDiv = document.getElementById('anomalies-list');
        anomaliesDiv.innerHTML = '';
        if (anomalies.length === 0) {
          anomaliesDiv.innerHTML = '<p style="color: #27ae60;">✓ No anomalies detected</p>';
        } else {
          for (const anom of anomalies) {
            anomaliesDiv.innerHTML += `<div class="alert alert-warning">
              <strong>${anom.hour}:</strong> ${anom.anomaly_type.toUpperCase()} detected (${anom.traffic} requests, Z-score: ${anom.z_score})
            </div>`;
          }
        }
        
        // Update timestamp
        document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
      } catch (err) {
        console.error('Error refreshing dashboard:', err);
        alert('Error loading analytics: ' + err.message);
      }
    }

    async function exportCSV() {
      try {
        const res = await fetch('/api/analytics/export/csv', {
          headers: csrfHeaders(),
        });
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'traffic_report.csv';
        a.click();
      } catch (err) {
        alert('Error exporting CSV: ' + err.message);
      }
    }

    async function exportPDF() {
      try {
        const res = await fetch('/api/analytics/export/pdf', {
          headers: csrfHeaders(),
        });
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'traffic_report.pdf';
        a.click();
      } catch (err) {
        alert('Error exporting PDF: ' + err.message);
      }
    }

    // Initial load
    refreshDashboard();
    
    // Auto-refresh every 30 seconds
    setInterval(refreshDashboard, 30000);
  </script>
</body>
</html>'''
    return HTMLResponse(html)


@app.get('/api/rules')
async def list_rules():
    return JSONResponse(config_manager.config.waf['rules'])


@app.get('/api/stats')
async def stats():
    if not redis_client:
        return JSONResponse({'request_count': 0, 'anomaly_count': 0, 'suspicious_ips': 0, 'blocked_ips': 0})
    request_count = await redis_client.get('proxy:request_count') or '0'
    anomaly_count = await redis_client.get('proxy:anomaly_count') or '0'
    rate_stats = await get_rate_limit_stats(redis_client)
    return JSONResponse({'request_count': int(request_count), 'anomaly_count': int(anomaly_count), **rate_stats})


@app.get('/api/activity')
async def activity():
    log_path = 'logs/proxy-events.jsonl'
    if not os.path.exists(log_path):
        return JSONResponse([])
    recent = []
    with open(log_path, 'r', encoding='utf-8') as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            recent.append({
                'event': item.get('event', 'request'),
                'timestamp': item.get('timestamp'),
                'path': item.get('path'),
                'client_ip': item.get('client_ip'),
            })
    return JSONResponse(recent[-10:])


@app.post('/api/rules/{rule_name}/toggle')
async def toggle_rule(rule_name: str):
    if rule_name not in config_manager.config.waf['rules']:
        return JSONResponse({'error': 'Unknown rule'}, status_code=404)
    current = config_manager.config.waf['rules'][rule_name]
    await config_manager.update_runtime_setting(f'waf.rules.{rule_name}', not current)
    return JSONResponse({'rule': rule_name, 'enabled': not current})


@app.get('/api/blocked_ips')
async def blocked_ips():
    ips = await get_blocked_ips(redis_client)
    return JSONResponse(ips)


@app.post('/api/ml/retrain')
async def retrain_ml():
    try:
        train_model()
        return JSONResponse({'status': 'ok'})
    except Exception as exc:
        return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=500)


# ============ Analytics Endpoints ============

@app.get('/api/analytics/dashboard')
async def analytics_dashboard():
    """Отримати повний дашборд аналітики"""
    hours = 24
    return JSONResponse({
        'traffic_stats': analytics.get_traffic_stats(hours),
        'top_waf_rules': analytics.get_top_waf_rules(limit=10, hours=hours),
        'top_blocked_ips': analytics.get_top_blocked_ips(limit=10, hours=hours),
        'traffic_by_method': analytics.get_traffic_by_method(hours),
        'traffic_by_status': analytics.get_traffic_by_status(hours),
        'hourly_traffic': analytics.get_hourly_traffic(hours),
        'top_paths': analytics.get_path_statistics(limit=15, hours=hours),
        'security_summary': analytics.get_security_summary(hours),
    })


@app.get('/api/analytics/traffic')
async def analytics_traffic(request: Request):
    """Статистика трафіку"""
    hours = int(request.query_params.get('hours', 24))
    return JSONResponse(analytics.get_traffic_stats(hours))


@app.get('/api/analytics/waf-rules')
async def analytics_waf_rules():
    """Топ порушених WAF правил"""
    hours = 24
    limit = 10
    return JSONResponse(analytics.get_top_waf_rules(limit=limit, hours=hours))


@app.get('/api/analytics/blocked-ips')
async def analytics_blocked_ips():
    """Топ заблокованих IP адрес"""
    hours = 24
    limit = 10
    return JSONResponse(analytics.get_top_blocked_ips(limit=limit, hours=hours))


@app.get('/api/analytics/hourly-traffic')
async def analytics_hourly():
    """Трафік по часам"""
    hours = 24
    return JSONResponse(analytics.get_hourly_traffic(hours))


@app.get('/api/analytics/anomalies')
async def analytics_anomalies():
    """Виявлені аномалії у трафіку"""
    hours = 24
    return JSONResponse(analytics.detect_anomalies(hours, threshold=2.0))


@app.get('/api/analytics/report')
async def analytics_report():
    """Детальний звіт"""
    hours = 24
    return JSONResponse(analytics.get_detailed_report(hours))


@app.get('/api/analytics/export/csv')
async def analytics_export_csv():
    """Експорт звіту в CSV"""
    try:
        import tempfile
        report_data = analytics.get_hourly_traffic(24)
        
        # Створити тимчасовий файл
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            import csv
            writer = csv.DictWriter(f, fieldnames=['hour', 'total', 'blocked'])
            writer.writeheader()
            writer.writerows(report_data)
            temp_path = f.name
        
        return FileResponse(temp_path, media_type='text/csv', filename='traffic_report.csv')
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/analytics/export/pdf')
async def analytics_export_pdf():
    """Експорт звіту в PDF"""
    try:
        import tempfile
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        
        report = analytics.get_detailed_report(24)
        
        # Створити PDF
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            pdf_path = f.name
        
        doc = SimpleDocTemplate(pdf_path, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=30,
        )
        
        # Заголовок
        story.append(Paragraph('Traffic Analytics Report', title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Трафік статистика
        story.append(Paragraph('Traffic Statistics', styles['Heading2']))
        traffic = report['traffic_stats']
        traffic_data = [
            ['Metric', 'Value'],
            ['Total Requests', str(traffic['total_requests'])],
            ['Blocked Requests', str(traffic['blocked_requests'])],
            ['WAF Blocks', str(traffic['waf_blocks'])],
            ['Block Rate (%)', str(traffic['block_rate'])],
        ]
        traffic_table = Table(traffic_data)
        traffic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(traffic_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Топ WAF правила
        story.append(Paragraph('Top WAF Rules', styles['Heading2']))
        waf_rules = report['top_waf_rules']
        if waf_rules:
            waf_data = [['Rule', 'Count']]
            for rule in waf_rules[:5]:
                waf_data.append([rule['rule'], str(rule['count'])])
            waf_table = Table(waf_data)
            waf_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(waf_table)
        else:
            story.append(Paragraph('No WAF blocks detected', styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Топ заблоковані IPs
        story.append(Paragraph('Top Blocked IPs', styles['Heading2']))
        blocked_ips = report['top_blocked_ips']
        if blocked_ips:
            ip_data = [['IP Address', 'Count']]
            for ip in blocked_ips[:5]:
                ip_data.append([ip['ip'], str(ip['count'])])
            ip_table = Table(ip_data)
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(ip_table)
        else:
            story.append(Paragraph('No blocked IPs', styles['Normal']))
        
        # Побудувати PDF
        doc.build(story)
        return FileResponse(pdf_path, media_type='application/pdf', filename='traffic_report.pdf')
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.websocket('/ws/config')
async def websocket_config(ws: WebSocket):
    # Respect admin.enabled flag for websocket access
    if not config_manager.config.admin.get('enabled', True):
        await ws.accept()
        await ws.close(code=1008)
        return

    expected_token = _get_expected_admin_token()
    if expected_token:
        provided_token = _get_provided_admin_token(ws)
        if not provided_token or not _constant_time_compare(provided_token, expected_token):
            await ws.accept()
            await ws.close(code=1008)
            return
    if not redis_client:
        await ws.accept()
        await ws.close(code=1008)
        return
    await ws.accept()
    pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
    await pubsub.subscribe('proxy:config_updates')
    try:
        async for message in pubsub.listen():
            if message and message.get('data'):
                await ws.send_text(json.dumps({'update': message['data']}))
    finally:
        await pubsub.unsubscribe('proxy:config_updates')
        await pubsub.close()

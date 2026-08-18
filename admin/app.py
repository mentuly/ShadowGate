import json
import logging
import os
import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from redis.asyncio import Redis

from proxy.config import ConfigManager
from proxy.model import train_model
from proxy.rate_limit import get_blocked_ips, get_rate_limit_stats, get_redis_client

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
  <title>Proxy Admin</title>
  <style>body { font-family: sans-serif; padding: 1rem; } .card { border: 1px solid #ddd; margin: 0.75rem 0; padding: 1rem; border-radius: 6px; }</style>
</head>
<body>
  <h1>Proxy Admin</h1>
  <div class="card">
    <h2>WAF Rules</h2>
    <div id="rules"></div>
  </div>
  <div class="card">
    <h2>Blocked / Suspicious IPs</h2>
    <div id="blocked"></div>
  </div>
  <div class="card">
    <h2>Live Stats</h2>
    <div id="stats"></div>
  </div>
  <div class="card">
    <h2>Recent Activity</h2>
    <div id="activity"></div>
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
      return await res.json();
    }

    async function refresh() {
        const rules = await fetchJson('/api/rules');
            const rulesDiv = document.getElementById('rules');
            rulesDiv.innerHTML = '';
            for (const [name, enabled] of Object.entries(rules)) {
                const btn = document.createElement('button');
                btn.textContent = enabled ? 'Disable' : 'Enable';
                btn.onclick = async () => {
                    await fetch(`/api/rules/${name}/toggle`, { method: 'POST', headers: csrfHeaders() });
                    refresh();
                };
                const item = document.createElement('div');
                item.textContent = name + ': ' + enabled;
                item.append(' ', btn);
                rulesDiv.appendChild(item);
            }
            const blocked = await fetchJson('/api/blocked_ips');
            const blockedDiv = document.getElementById('blocked');
            blockedDiv.innerHTML = '';
            if (!blocked || blocked.length === 0) {
                const noDiv = document.createElement('div');
                noDiv.textContent = 'No blocked IPs';
                blockedDiv.appendChild(noDiv);
            } else {
                for (const item of blocked) {
                    const d = document.createElement('div');
                    d.textContent = `${item.ip} — score ${item.score}`;
                    blockedDiv.appendChild(d);
                }
            }
            const stats = await fetchJson('/api/stats');
            const statsDiv = document.getElementById('stats');
            statsDiv.innerHTML = '';
            statsDiv.appendChild(Object.assign(document.createElement('div'), { textContent: `Request count: ${stats.request_count}` }));
            statsDiv.appendChild(Object.assign(document.createElement('div'), { textContent: `Anomaly blocks: ${stats.anomaly_count}` }));
            statsDiv.appendChild(Object.assign(document.createElement('div'), { textContent: `Suspicious IPs: ${stats.suspicious_ips}` }));
            statsDiv.appendChild(Object.assign(document.createElement('div'), { textContent: `Blocked IPs: ${stats.blocked_ips}` }));
            const retrainBtn = document.createElement('button');
            retrainBtn.textContent = 'Retrain ML model';
            retrainBtn.onclick = () => fetch('/api/ml/retrain', { method: 'POST', headers: csrfHeaders() }).then(() => refresh());
            statsDiv.appendChild(retrainBtn);
            const activity = await fetchJson('/api/activity');
            const activityDiv = document.getElementById('activity');
            activityDiv.innerHTML = '';
            if (!activity || activity.length === 0) {
                const noAct = document.createElement('div');
                noAct.textContent = 'No recent activity';
                activityDiv.appendChild(noAct);
            } else {
                for (const item of activity) {
                    const a = document.createElement('div');
                    a.textContent = `${item.timestamp}: ${item.event} :: ${item.path || '-'} :: ${item.client_ip || '-'}`;
                    activityDiv.appendChild(a);
                }
            }
    }
    refresh();
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws/config');
    ws.onmessage = () => refresh();
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

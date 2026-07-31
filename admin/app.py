import json
import logging
import os
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
    if isinstance(request, WebSocket):
        headers = request.headers
    else:
        headers = request.headers
    token = headers.get('x-admin-token')
    if token:
        return token
    auth_header = headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:].strip()
    return None


@app.middleware('http')
async def require_admin_auth(request: Request, call_next):
    expected_token = _get_expected_admin_token()
    if not expected_token:
        return JSONResponse({'detail': 'Admin authentication required'}, status_code=401)

    provided_token = _get_provided_admin_token(request)
    if provided_token != expected_token:
        return JSONResponse({'detail': 'Admin authentication required'}, status_code=401)

    return await call_next(request)


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
    async function fetchJson(path) {
      const res = await fetch(path);
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
          await fetch(`/api/rules/${name}/toggle`, { method: 'POST' });
          refresh();
        };
        const item = document.createElement('div');
        item.textContent = name + ': ' + enabled;
        item.append(' ', btn);
        rulesDiv.appendChild(item);
      }
      const blocked = await fetchJson('/api/blocked_ips');
      const blockedDiv = document.getElementById('blocked');
      blockedDiv.innerHTML = blocked.map(item => `<div>${item.ip} — score ${item.score}</div>`).join('') || '<div>No blocked IPs</div>';
      const stats = await fetchJson('/api/stats');
      const statsDiv = document.getElementById('stats');
      statsDiv.innerHTML = `<div>Request count: ${stats.request_count}</div><div>Anomaly blocks: ${stats.anomaly_count}</div><div>Suspicious IPs: ${stats.suspicious_ips}</div><div>Blocked IPs: ${stats.blocked_ips}</div><button onclick="fetch('/api/ml/retrain', {method:'POST'}).then(() => refresh())">Retrain ML model</button>`;
      const activity = await fetchJson('/api/activity');
      const activityDiv = document.getElementById('activity');
      activityDiv.innerHTML = activity.map(item => `<div>${item.timestamp}: ${item.event} :: ${item.path || '-'} :: ${item.client_ip || '-'}</div>`).join('') || '<div>No recent activity</div>';
    }
    refresh();
    const ws = new WebSocket(`ws://${location.host}/ws/config`);
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
    expected_token = _get_expected_admin_token()
    if expected_token and _get_provided_admin_token(ws) != expected_token:
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

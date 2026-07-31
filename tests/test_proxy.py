import importlib
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxy.app import app, config_manager
from proxy.waf import scan_request_components


class _BackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'hello from backend')

    def log_message(self, format, *args):
        return


def _make_request(app_instance, method: str, url: str, **kwargs) -> httpx.Response:
    async def _request() -> httpx.Response:
        async with app_instance.router.lifespan_context(app_instance):
            transport = httpx.ASGITransport(app=app_instance)
            async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as client:
                return await client.request(method, url, **kwargs)

    import asyncio
    return asyncio.run(_request())


def test_proxy_forwards_http_requests():
    server = HTTPServer(('127.0.0.1', 0), _BackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        os.environ['PROXY_TARGET'] = f'http://127.0.0.1:{server.server_address[1]}'
        os.environ['WAF_ENABLED'] = 'false'
        config_manager.reload_from_file()
        response = _make_request(app, 'GET', '/hello')
        assert response.status_code == 200
        assert response.text == 'hello from backend'
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_proxy_blocks_malicious_requests_with_waf():
    os.environ['PROXY_TARGET'] = 'http://127.0.0.1:1'
    os.environ['WAF_ENABLED'] = 'true'
    config_manager.reload_from_file()
    config_manager.config.waf['rules'] = {
        'sql_injection': True,
        'xss': True,
        'path_traversal': True,
    }
    response = _make_request(app, 'GET', '/hello?<script>')
    assert response.status_code == 403
    assert 'Forbidden' in response.text


def test_proxy_rejects_absolute_url_targets():
    os.environ['PROXY_TARGET'] = 'http://127.0.0.1:1'
    os.environ['WAF_ENABLED'] = 'false'
    config_manager.reload_from_file()
    response = _make_request(app, 'GET', '/http://127.0.0.1:1/evil')
    assert response.status_code == 400
    assert 'blocked' in response.text.lower()


def test_admin_requires_authentication():
    os.environ['ADMIN_AUTH_TOKEN'] = 'test-token'
    import admin.app as admin_app_module
    admin_app_module = importlib.reload(admin_app_module)
    response = _make_request(admin_app_module.app, 'GET', '/')
    assert response.status_code == 401
    auth_response = _make_request(admin_app_module.app, 'GET', '/', headers={'X-Admin-Token': 'test-token'})
    assert auth_response.status_code == 200


def test_waf_detects_obfuscated_sql_and_headers():
    result = scan_request_components(
        '/api',
        'name=SEL%252F%252FECT%2520*%2520FROM%2520users',
        '',
        {'sql_injection': True, 'xss': True, 'path_traversal': True},
        headers={'x-test': '<script>alert(1)</script>'},
    )
    assert result is not None
    assert result[1] in {'sql_injection', 'xss'}

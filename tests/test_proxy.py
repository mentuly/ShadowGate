import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxy.app import app, config_manager


class _BackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'hello from backend')

    def log_message(self, format, *args):
        return


def test_proxy_forwards_http_requests():
    server = HTTPServer(('127.0.0.1', 0), _BackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        os.environ['PROXY_TARGET'] = f'http://127.0.0.1:{server.server_address[1]}'
        config_manager.reload_from_file()
        with TestClient(app) as client:
            config_manager.config.waf['enabled'] = False
            response = client.get('/hello')
            assert response.status_code == 200
            assert response.text == 'hello from backend'
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_proxy_blocks_malicious_requests_with_waf():
    os.environ['PROXY_TARGET'] = 'http://127.0.0.1:1'
    config_manager.reload_from_file()
    with TestClient(app) as client:
        config_manager.config.waf['enabled'] = True
        config_manager.config.waf['rules'] = {
            'sql_injection': True,
            'xss': True,
            'path_traversal': True,
        }
        response = client.get('/hello?<script>')
        assert response.status_code == 403
        assert 'Forbidden' in response.text

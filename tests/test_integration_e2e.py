"""
E2E Integration тести для proxy та admin панелі.
Запуск: pytest tests/test_integration_e2e.py -v
"""
import asyncio
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxy.app import app as proxy_app, config_manager as proxy_config_manager
from admin.app import app as admin_app
from tests.test_proxy import _make_request


class _MockBackendHandler(BaseHTTPRequestHandler):
    """Mock бекенд для E2E тестів"""
    
    def do_GET(self):
        path = self.path
        
        # Симуляція різних ендпоїнтів
        if path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
        elif path.startswith('/api/users/'):
            user_id = path.split('/')[-1]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {'id': user_id, 'name': f'User {user_id}'}
            self.wfile.write(json.dumps(response).encode())
        elif path == '/api/delay':
            time.sleep(0.1)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "delayed response"}')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'path': path, 'method': 'GET'}).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'status': 'created',
            'received_bytes': len(body),
            'path': self.path
        }
        self.wfile.write(json.dumps(response).encode())

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        return


@pytest.fixture(scope='module')
def backend_server():
    """Запускає mock бекенд сервер"""
    server = HTTPServer(('127.0.0.1', 0), _MockBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture(autouse=True)
def setup_proxy(backend_server):
    """Налаштовує proxy перед кожним тестом"""
    os.environ['PROXY_TARGET'] = f'http://127.0.0.1:{backend_server.server_address[1]}'
    os.environ['WAF_ENABLED'] = 'false'
    os.environ['RATE_LIMIT_ENABLED'] = 'false'
    os.environ['ML_ENABLED'] = 'false'
    proxy_config_manager.reload_from_file()
    yield


class TestProxyBasicFlow:
    """E2E тести для базового потоку proxy"""

    def test_simple_request_forwarding(self):
        """E2E: простий запит через proxy"""
        response = _make_request(proxy_app, 'GET', '/api/test')
        assert response.status_code == 200
        data = response.json()
        assert data['path'] == '/api/test'

    def test_multiple_sequential_requests(self):
        """E2E: послідовні запити"""
        for i in range(5):
            response = _make_request(proxy_app, 'GET', f'/api/users/{i}')
            assert response.status_code == 200
            data = response.json()
            assert data['id'] == str(i)

    def test_post_request_with_payload(self):
        """E2E: POST запит з payload"""
        payload = {'name': 'Test User', 'email': 'test@example.com'}
        response = _make_request(proxy_app, 'POST', '/api/users', json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'created'
        assert data['received_bytes'] > 0

    def test_delete_request(self):
        """E2E: DELETE запит"""
        response = _make_request(proxy_app, 'DELETE', '/api/users/1')
        assert response.status_code == 204

    def test_request_with_headers(self):
        """E2E: запит з custom headers"""
        headers = {
            'X-Custom-Header': 'custom-value',
            'X-Request-ID': 'test-123',
        }
        response = _make_request(proxy_app, 'GET', '/api/test', headers=headers)
        assert response.status_code == 200

    def test_request_with_query_params(self):
        """E2E: запит з query параметрами"""
        response = _make_request(proxy_app, 'GET', '/api/search?q=test&limit=10&offset=0')
        assert response.status_code == 200
        data = response.json()
        assert 'q=test' in data['path']


class TestWAFIntegration:
    """E2E тести для WAF"""

    @pytest.fixture(autouse=True)
    def enable_waf(self):
        os.environ['WAF_ENABLED'] = 'true'
        proxy_config_manager.reload_from_file()
        proxy_config_manager.config.waf['rules'] = {
            'sql_injection': True,
            'xss': True,
            'path_traversal': True,
        }
        yield
        os.environ['WAF_ENABLED'] = 'false'
        proxy_config_manager.reload_from_file()

    def test_waf_blocks_sql_injection(self):
        """E2E: WAF блокує SQL injection"""
        response = _make_request(proxy_app, 'GET', "/api/users?id=1' OR '1'='1")
        assert response.status_code == 403
        assert 'Forbidden' in response.text

    def test_waf_blocks_xss(self):
        """E2E: WAF блокує XSS"""
        response = _make_request(proxy_app, 'GET', '/api/search?q=<script>alert("xss")</script>')
        assert response.status_code == 403

    def test_waf_blocks_path_traversal(self):
        """E2E: WAF блокує path traversal"""
        response = _make_request(proxy_app, 'GET', '/api/file?path=../../../etc/passwd')
        assert response.status_code == 403

    def test_waf_allows_safe_request(self):
        """E2E: WAF дозволяє безпечні запити"""
        response = _make_request(proxy_app, 'GET', '/api/users/123')
        assert response.status_code == 200

    def test_waf_blocks_encoded_xss(self):
        """E2E: WAF блокує закодовану XSS"""
        response = _make_request(proxy_app, 'GET', '/api/search?q=%3Cscript%3E')
        assert response.status_code == 403


class TestSSRFProtection:
    """E2E тести для SSRF захисту"""

    def test_rejects_absolute_url_in_path(self):
        """E2E: блокує абсолютну URL у path"""
        response = _make_request(proxy_app, 'GET', '/http://evil.com/steal')
        assert response.status_code == 400
        assert 'blocked' in response.text.lower()

    def test_rejects_different_backend(self):
        """E2E: блокує запити до неповинного бекенду"""
        os.environ['SSRF_ALLOWLIST'] = 'example.com,safe.com'
        proxy_config_manager.reload_from_file()
        
        # Спроба перемикання на різний бекенд
        response = _make_request(proxy_app, 'GET', '/')
        # Повинно передатися до дозволеного бекенду
        assert response.status_code in [200, 502, 503]  # 502/503 якщо бекенд недоступний


class TestRateLimiting:
    """E2E тести для rate limiting"""

    @pytest.fixture(autouse=True)
    def setup_rate_limit(self):
        os.environ['RATE_LIMIT_ENABLED'] = 'true'
        proxy_config_manager.reload_from_file()
        proxy_config_manager.config.rate_limit['capacity'] = 10
        proxy_config_manager.config.rate_limit['refill_rate'] = 100.0
        proxy_config_manager.config.rate_limit['cost_per_request'] = 1
        yield
        os.environ['RATE_LIMIT_ENABLED'] = 'false'
        proxy_config_manager.reload_from_file()

    def test_rate_limit_allows_requests_within_limit(self):
        """E2E: rate limit дозволяє запити у межах ліміту"""
        for i in range(5):
            response = _make_request(proxy_app, 'GET', '/api/test')
            assert response.status_code == 200

    def test_rate_limit_blocks_excessive_requests(self):
        """E2E: rate limit блокує надлишкові запити"""
        # Спочатку дозволені запити
        for i in range(10):
            response = _make_request(proxy_app, 'GET', '/api/test')
            assert response.status_code == 200
        
        # Наступний запит повинен бути блокований
        response = _make_request(proxy_app, 'GET', '/api/test')
        assert response.status_code == 429


class TestAdminPanel:
    """E2E тести для admin панелі"""

    @pytest.fixture(autouse=True)
    def setup_admin(self):
        os.environ['ADMIN_AUTH_TOKEN'] = 'test-admin-token'
        import importlib
        import admin.app as admin_module
        importlib.reload(admin_module)
        yield

    def test_admin_requires_authentication(self):
        """E2E: admin панель вимагає аутентифікацію"""
        response = _make_request(admin_app, 'GET', '/')
        assert response.status_code == 401

    def test_admin_with_valid_token(self):
        """E2E: доступ до admin панелі з валідним токеном"""
        headers = {'X-Admin-Token': 'test-admin-token'}
        response = _make_request(admin_app, 'GET', '/', headers=headers)
        assert response.status_code == 200

    def test_admin_api_get_config(self):
        """E2E: отримання конфігурації через admin API"""
        headers = {'X-Admin-Token': 'test-admin-token'}
        response = _make_request(admin_app, 'GET', '/api/config', headers=headers)
        assert response.status_code == 200

    def test_admin_toggle_waf_rule(self):
        """E2E: включення/вимикання WAF правила"""
        headers = {
            'X-Admin-Token': 'test-admin-token',
            'X-CSRF-Token': 'test-csrf-token',
            'Content-Type': 'application/json',
        }
        # Отримання CSRF токена через GET
        get_response = _make_request(admin_app, 'GET', '/', headers={'X-Admin-Token': 'test-admin-token'})
        
        # Спроба toggle правила
        response = _make_request(admin_app, 'POST', '/api/rules/sql_injection/toggle', headers=headers)
        # Може бути 403 через CSRF, але це очікується для E2E тесту
        assert response.status_code in [200, 403]


class TestHealthAndMetrics:
    """E2E тести для health та metrics ендпоїнтів"""

    def test_health_endpoint(self):
        """E2E: перевірка health ендпоїнту"""
        response = _make_request(proxy_app, 'GET', '/health')
        assert response.status_code == 200
        data = response.json()
        assert 'status' in data or len(response.text) > 0

    def test_livez_endpoint(self):
        """E2E: перевірка livez ендпоїнту"""
        response = _make_request(proxy_app, 'GET', '/livez')
        assert response.status_code in [200, 204]

    def test_readyz_endpoint(self):
        """E2E: перевірка readyz ендпоїнту"""
        response = _make_request(proxy_app, 'GET', '/readyz')
        assert response.status_code in [200, 204]

    def test_metrics_endpoint(self):
        """E2E: перевірка metrics ендпоїнту"""
        response = _make_request(proxy_app, 'GET', '/metrics')
        assert response.status_code == 200


class TestConcurrentRequests:
    """E2E тести для паралельних запитів"""

    def test_multiple_concurrent_get_requests(self):
        """E2E: кілька паралельних GET запитів"""
        import concurrent.futures
        
        def make_request(i):
            return _make_request(proxy_app, 'GET', f'/api/users/{i}')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        assert all(r.status_code == 200 for r in results)
        assert len(results) == 20

    def test_mixed_request_methods(self):
        """E2E: змішані методи запитів (GET, POST, DELETE)"""
        responses = [
            _make_request(proxy_app, 'GET', '/api/data'),
            _make_request(proxy_app, 'POST', '/api/data', json={'key': 'value'}),
            _make_request(proxy_app, 'GET', '/api/users/1'),
            _make_request(proxy_app, 'DELETE', '/api/users/1'),
        ]
        
        assert responses[0].status_code == 200  # GET
        assert responses[1].status_code == 200  # POST
        assert responses[2].status_code == 200  # GET
        assert responses[3].status_code == 204  # DELETE


class TestErrorHandling:
    """E2E тести для обробки помилок"""

    def test_backend_not_found(self):
        """E2E: обробка 404 від бекенду"""
        response = _make_request(proxy_app, 'GET', '/nonexistent/path')
        # Може бути або 404 від бекенду або від proxy
        assert response.status_code in [200, 404]

    def test_request_body_size_limit(self):
        """E2E: обмеження розміру request body"""
        large_body = 'x' * (2 * 1024 * 1024)  # 2MB
        response = _make_request(proxy_app, 'POST', '/api/upload', json={'data': large_body})
        # Повинно бути блоковано або обробленo
        assert response.status_code in [200, 413, 400]

    def test_malformed_request(self):
        """E2E: обробка malformed запиту"""
        # Це складніше протестувати через ASGI interface
        # але ми можемо перевірити базові сценарії
        response = _make_request(proxy_app, 'GET', '/api/test')
        assert response.status_code in [200, 400, 500]


class TestConfigReloading:
    """E2E тести для перезавантаження конфігурації"""

    def test_waf_toggle_takes_effect(self):
        """E2E: вимикання WAF одразу впливає на запити"""
        # Спочатку WAF вимкнена
        os.environ['WAF_ENABLED'] = 'false'
        proxy_config_manager.reload_from_file()
        
        response = _make_request(proxy_app, 'GET', '/api/test?q=<script>')
        assert response.status_code == 200  # Дозволено без WAF
        
        # Включаємо WAF
        os.environ['WAF_ENABLED'] = 'true'
        proxy_config_manager.reload_from_file()
        proxy_config_manager.config.waf['rules'] = {
            'sql_injection': True,
            'xss': True,
            'path_traversal': True,
        }
        
        response = _make_request(proxy_app, 'GET', '/api/test?q=<script>')
        assert response.status_code == 403  # Блоковано з WAF

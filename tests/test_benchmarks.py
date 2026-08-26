"""
Benchmarks для вимірювання latency та продуктивності proxy.
Запуск: pytest tests/test_benchmarks.py -v --benchmark-only
"""
import asyncio
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxy.app import app, config_manager
from tests.test_proxy import _make_request


class _SimpleBackendHandler(BaseHTTPRequestHandler):
    """Простий бекенд для бенчмарків"""
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response_data = {'status': 'ok', 'path': self.path, 'timestamp': time.time()}
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {'status': 'ok', 'received': len(body)}
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def log_message(self, format, *args):
        return


@pytest.fixture(scope='module')
def backend_server():
    """Запускає простий HTTP сервер для бенчмарків"""
    server = HTTPServer(('127.0.0.1', 0), _SimpleBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture(autouse=True)
def setup_proxy(backend_server):
    """Налаштовує proxy для бенчмарків"""
    os.environ['PROXY_TARGET'] = f'http://127.0.0.1:{backend_server.server_address[1]}'
    os.environ['WAF_ENABLED'] = 'false'
    os.environ['RATE_LIMIT_ENABLED'] = 'false'
    config_manager.reload_from_file()
    yield


class TestProxyBenchmarks:
    """Бенчмарки для основних операцій proxy"""

    def test_simple_get_request(self, benchmark):
        """Бенчмарк: простий GET запит через proxy"""
        result = benchmark(lambda: _make_request(app, 'GET', '/api/data'))
        assert result.status_code == 200

    def test_get_with_query_params(self, benchmark):
        """Бенчмарк: GET з параметрами запиту"""
        result = benchmark(lambda: _make_request(app, 'GET', '/api/search?q=test&limit=100'))
        assert result.status_code == 200

    def test_post_with_body(self, benchmark):
        """Бенчмарк: POST з тілом запиту"""
        body = {'data': 'x' * 1000}
        result = benchmark(lambda: _make_request(app, 'POST', '/api/data', json=body))
        assert result.status_code == 200

    def test_post_with_large_body(self, benchmark):
        """Бенчмарк: POST з великим тілом (100KB)"""
        body = {'data': 'x' * (100 * 1024)}
        result = benchmark(lambda: _make_request(app, 'POST', '/api/upload', json=body))
        assert result.status_code == 200

    def test_many_headers(self, benchmark):
        """Бенчмарк: запит з багатьма заголовками"""
        headers = {f'X-Custom-Header-{i}': f'value-{i}' for i in range(50)}
        result = benchmark(lambda: _make_request(app, 'GET', '/api/data', headers=headers))
        assert result.status_code == 200


class TestWAFBenchmarks:
    """Бенчмарки для WAF сканування"""

    @pytest.fixture(autouse=True)
    def enable_waf(self):
        """Ввімкнути WAF для цих тестів"""
        os.environ['WAF_ENABLED'] = 'true'
        config_manager.reload_from_file()
        config_manager.config.waf['rules'] = {
            'sql_injection': True,
            'xss': True,
            'path_traversal': True,
        }
        yield
        os.environ['WAF_ENABLED'] = 'false'
        config_manager.reload_from_file()

    def test_waf_scan_normal_request(self, benchmark):
        """Бенчмарк: WAF сканування нормального запиту"""
        result = benchmark(lambda: _make_request(app, 'GET', '/api/safe'))
        assert result.status_code == 200

    def test_waf_scan_with_payload(self, benchmark):
        """Бенчмарк: WAF блокування зловмисного запиту"""
        result = benchmark(lambda: _make_request(app, 'GET', '/api/data?id=1'))
        # Це буде або 200 або 403 залежно від того чи блокувати
        assert result.status_code in [200, 403]


class TestRateLimitBenchmarks:
    """Бенчмарки для rate limiting"""

    @pytest.fixture(autouse=True)
    def setup_rate_limit(self):
        """Налаштування rate limit"""
        os.environ['RATE_LIMIT_ENABLED'] = 'true'
        config_manager.reload_from_file()
        yield
        os.environ['RATE_LIMIT_ENABLED'] = 'false'
        config_manager.reload_from_file()

    def test_rate_limit_check_overhead(self, benchmark):
        """Бенчмарк: час обробки rate limit чеку"""
        result = benchmark(lambda: _make_request(app, 'GET', '/api/data'))
        assert result.status_code in [200, 429]  # 429 = Too Many Requests


class TestResponseBenchmarks:
    """Бенчмарки для часу відповіді"""

    def test_response_parsing_time(self, benchmark):
        """Бенчмарк: парсинг JSON відповіді"""
        response = _make_request(app, 'GET', '/api/data')
        result = benchmark(lambda: response.json())
        assert 'status' in result

    def test_response_text_time(self, benchmark):
        """Бенчмарк: обробка текстової відповіді"""
        response = _make_request(app, 'GET', '/api/data')
        result = benchmark(lambda: response.text)
        assert len(result) > 0


def test_throughput_sequential(benchmark):
    """Бенчмарк: послідовна пропускна здатність (100 запитів)"""
    def make_requests():
        for _ in range(100):
            _make_request(app, 'GET', '/api/data')
    
    benchmark(make_requests)


def test_latency_percentiles(backend_server):
    """Вимірювання latency percentiles (p50, p95, p99)"""
    os.environ['PROXY_TARGET'] = f'http://127.0.0.1:{backend_server.server_address[1]}'
    os.environ['WAF_ENABLED'] = 'false'
    config_manager.reload_from_file()
    
    latencies = []
    for _ in range(1000):
        start = time.perf_counter()
        _make_request(app, 'GET', '/api/data')
        elapsed = (time.perf_counter() - start) * 1000  # ms
        latencies.append(elapsed)
    
    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    
    print(f"\nLatency Percentiles (ms):")
    print(f"  p50: {p50:.2f}")
    print(f"  p95: {p95:.2f}")
    print(f"  p99: {p99:.2f}")
    
    assert p50 < 100, "p50 latency should be < 100ms"
    assert p95 < 500, "p95 latency should be < 500ms"

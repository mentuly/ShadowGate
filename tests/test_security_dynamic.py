import importlib
import os
import sys
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_proxy import _make_request


def test_xss_logging_sanitized():
    # Ensure WAF is disabled so request is accepted and logged
    os.environ['WAF_ENABLED'] = 'false'
    os.environ['PROXY_TARGET'] = 'http://127.0.0.1:1'
    import proxy.app as proxy_app_module
    import admin.app as admin_app_module
    proxy_app_module = importlib.reload(proxy_app_module)
    admin_app_module = importlib.reload(admin_app_module)

    # Remove existing log
    log_path = Path('logs/proxy-events.jsonl')
    if log_path.exists():
        log_path.unlink()

    # Send a request with an XSS-like path
    dangerous_path = '/<script>alert(1)</script>'
    res = _make_request(proxy_app_module.app, 'GET', dangerous_path)
    assert res.status_code in (200, 502, 502, 400, 404)

    # Now fetch admin activity and ensure path is sanitized (percent-encoded)
    os.environ['ADMIN_AUTH_TOKEN'] = 'test-token'
    admin_app_module = importlib.reload(admin_app_module)
    activity_res = _make_request(admin_app_module.app, 'GET', '/api/activity', headers={'X-Admin-Token': 'test-token'})
    assert activity_res.status_code == 200
    data = activity_res.json()
    assert isinstance(data, list)
    if data:
        # path should not contain raw '<' or '>' characters
        path = data[-1].get('path', '')
        assert '<' not in (path or '') and '>' not in (path or '')
        # and we expect percent-encoding for '<'
        assert '%3C' in path or '%3c' in path


def test_ssrf_rejection():
    import proxy.app as proxy_app_module
    proxy_app_module = importlib.reload(proxy_app_module)
    with __import__('pytest').raises(ValueError):
        proxy_app_module._build_backend_url('/path', raw_path=b'//http://example.com/')

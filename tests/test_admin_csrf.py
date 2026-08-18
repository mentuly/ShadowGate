import importlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_proxy import _make_request


def test_admin_rejects_post_without_csrf_header():
    os.environ['ADMIN_AUTH_TOKEN'] = 'test-token'
    import admin.app as admin_app_module
    admin_app_module = importlib.reload(admin_app_module)
    # Perform an authenticated GET to receive Set-Cookie headers
    res = _make_request(admin_app_module.app, 'GET', '/', headers={'X-Admin-Token': 'test-token'})
    assert res.status_code == 200
    set_cookie = res.headers.get('set-cookie') or res.headers.get('Set-Cookie') or ''
    m = re.search(r'admin_csrf=([^;\s]+)', set_cookie)
    assert m, 'admin_csrf cookie was not set in GET response'
    csrf_cookie = m.group(1)

    # Now POST to toggle a rule without sending X-CSRF-Token header, but including cookies
    cookie_header = f'admin_token=test-token; admin_csrf={csrf_cookie}'
    post_res = _make_request(admin_app_module.app, 'POST', '/api/rules/sql_injection/toggle', headers={'Cookie': cookie_header, 'X-Admin-Token': 'test-token'})
    assert post_res.status_code == 403
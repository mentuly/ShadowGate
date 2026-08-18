import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_proxy import _make_request


def test_admin_accepts_non_ascii_header():
    # Simulate an environment variable that contains raw Latin-1 bytes
    token_bytes = b'caf\xe9'
    # Decode using surrogateescape to simulate how os.environ may present non-UTF8 bytes
    env_token = token_bytes.decode('utf-8', 'surrogateescape')
    os.environ['ADMIN_AUTH_TOKEN'] = env_token

    import admin.app as admin_app_module
    admin_app_module = importlib.reload(admin_app_module)

    # Send header as raw bytes to simulate a Latin-1 HTTP header (httpx accepts bytes)
    res = _make_request(admin_app_module.app, 'GET', '/', headers={'X-Admin-Token': token_bytes})
    # Should not crash and should authenticate
    assert res.status_code == 200

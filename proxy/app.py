import asyncio
import contextlib
import json
import logging
import os
import re
import tempfile
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
import websockets
from fastapi import FastAPI, Request, Response, WebSocket, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from redis.asyncio import Redis

from proxy.config import ConfigManager
from proxy.model import AnomalyModel, log_request_features
from proxy.rate_limit import evaluate_request, get_redis_client, render_rate_limit_page
from proxy.waf import render_blocked_page, scan_request_components


def get_env(name: str, default: str | None = None) -> str:
    return os.getenv(name, default if default is not None else '')


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger('proxy')
EVENT_LOG_PATH = Path('logs/proxy-events.jsonl')
MAX_REQUEST_BODY_BYTES = 1_000_000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _log_event(event: str, **context) -> None:
    payload = {'event': event, 'timestamp': _now_iso(), **context}
    logger.info(json.dumps(payload, default=str, ensure_ascii=False))

@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    await _ensure_runtime_initialized()
    try:
        yield
    finally:
        await config_manager.shutdown()
        if redis_client:
            await redis_client.close()
        if hasattr(app_instance.state, 'client'):
            await app_instance.state.client.aclose()
        if getattr(app_instance.state, 'retrain_task', None):
            app_instance.state.retrain_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await app_instance.state.retrain_task


app = FastAPI(title='Async Reverse Proxy', version='1.1.0', lifespan=lifespan)

config_file = os.getenv('CONFIG_FILE', 'config.yaml')
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
config_manager = ConfigManager(config_file, redis_url=redis_url)
redis_client: Redis | None = None
anomaly_model: AnomalyModel | None = None


@app.middleware('http')
async def request_id_middleware(request: Request, call_next):
    if config_manager.config.observability.get('enable_request_id', True):
        request_id = request.headers.get('x-request-id') or uuid.uuid4().hex
        request.state.request_id = request_id
    else:
        request.state.request_id = None
    response = await call_next(request)
    if request.state.request_id is not None:
        response.headers['X-Request-ID'] = request.state.request_id
    return response


class TempFileByteStream(httpx.AsyncByteStream):
    def __init__(self, body_file: tempfile.SpooledTemporaryFile, chunk_size: int = 8192):
        self.body_file = body_file
        self.chunk_size = chunk_size

    async def __aiter__(self):
        self.body_file.seek(0)
        while True:
            chunk = self.body_file.read(self.chunk_size)
            if not chunk:
                break
            yield chunk
        self.body_file.seek(0)


async def _ensure_runtime_initialized() -> None:
    global redis_client, anomaly_model
    if getattr(app.state, 'runtime_initialized', False):
        return
    await config_manager.initialize()
    try:
        redis_client = get_redis_client(redis_url)
        await redis_client.ping()
    except Exception:
        redis_client = None
        logging.warning('Redis is unavailable, continuing without persistence features.')
    anomaly_model = AnomalyModel(threshold=config_manager.config.ml.get('anomaly_threshold', 0.0))
    if not hasattr(app.state, 'client') or getattr(app.state.client, 'is_closed', False):
        app.state.client = httpx.AsyncClient(timeout=None, follow_redirects=False)
    app.state.runtime_initialized = True
    if config_manager.config.ml.get('enabled', False) and anomaly_model is not None:
        app.state.retrain_task = asyncio.create_task(_retrain_loop())


async def _retrain_loop() -> None:
    while True:
        await asyncio.sleep(60)
        if not config_manager.config.ml.get('enabled', False) or anomaly_model is None:
            continue
        try:
            await asyncio.to_thread(anomaly_model.retrain_if_needed)
        except Exception:
            continue


def _append_event_log(event: dict) -> None:
    EVENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(EVENT_LOG_PATH, 'a', encoding='utf-8') as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + '\n')


async def _read_request_body(request: Request, max_memory_size: int = 65536, max_total_size: int = MAX_REQUEST_BODY_BYTES) -> tuple[int, tempfile.SpooledTemporaryFile]:
    body_file = tempfile.SpooledTemporaryFile(max_size=max_memory_size)
    total_size = 0
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            total_size += len(chunk)
            if total_size > max_total_size:
                raise ValueError(f'Request body exceeds the maximum allowed size of {max_total_size} bytes.')
            body_file.write(chunk)
    except ValueError:
        body_file.close()
        raise
    body_file.seek(0)
    return total_size, body_file


def _read_body_text(body_file: tempfile.SpooledTemporaryFile) -> str:
    body_file.seek(0)
    chunks = []
    while True:
        chunk = body_file.read(8192)
        if not chunk:
            break
        chunks.append(chunk.decode('utf-8', errors='replace'))
    body_file.seek(0)
    return ''.join(chunks)


async def _get_request_frequency(client_ip: str) -> int:
    if not redis_client:
        return 1
    try:
        key = f'proxy:request_freq:{client_ip}'
        value = await redis_client.incr(key)
        await redis_client.expire(key, 3600)
        return int(value)
    except Exception:
        return 1


async def _increment_stat(name: str) -> None:
    if not redis_client:
        return
    try:
        await redis_client.incr(name)
        await redis_client.expire(name, 86400)
    except Exception:
        return


def _matches_allowlist(hostname: str | None, allowlist: list[str]) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower().strip().rstrip('.')
    for allowed in allowlist:
        allowed = allowed.lower().strip().rstrip('.')
        if not allowed:
            continue
        if hostname == allowed or hostname.endswith(f'.{allowed}'):
            return True
    return False


def _build_backend_url(path: str, query_string: str | None = None, raw_path: bytes | str | None = None) -> str:
    target_base = config_manager.config.target_backend.rstrip('/')
    candidate_path = path.strip()
    if raw_path:
        raw_candidate = raw_path.decode('utf-8', 'surrogateescape') if isinstance(raw_path, (bytes, bytearray)) else str(raw_path)
        if raw_candidate.startswith('//'):
            raise ValueError('Blocked absolute URL target')
        raw_candidate = urllib.parse.unquote(raw_candidate)
        if raw_candidate.startswith('//'):
            raise ValueError('Blocked absolute URL target')
        if re.match(r'^/{2,}[a-zA-Z][a-zA-Z0-9+.-]*://', raw_candidate):
            raise ValueError('Blocked absolute URL target')
    if not candidate_path:
        candidate_path = '/'
    if candidate_path.startswith('//'):
        raise ValueError('Blocked absolute URL target')
    parsed_path = urllib.parse.urlsplit(candidate_path)
    if parsed_path.scheme or parsed_path.netloc:
        raise ValueError('Blocked absolute URL target')
    candidate_path = candidate_path.lstrip('/')
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', candidate_path):
        raise ValueError('Blocked absolute URL target')
    backend_url = urllib.parse.urljoin(target_base + '/', candidate_path)
    parsed_backend = urllib.parse.urlsplit(backend_url)
    allowlist = [item.strip() for item in config_manager.config.ssrf_allowlist if item and item.strip()]
    if allowlist and not _matches_allowlist(parsed_backend.hostname, allowlist):
        raise ValueError('Blocked absolute URL target')
    if query_string:
        backend_url = f'{backend_url}?{query_string}'
    return backend_url


async def _proxy_request(request: Request, path: str) -> Response:
    await _ensure_runtime_initialized()
    try:
        backend_url = _build_backend_url(path, request.url.query, request.scope.get('raw_path'))
    except ValueError:
        return HTMLResponse('<h1>400 Bad Request</h1><p>Blocked request to an external host.</p>', status_code=status.HTTP_400_BAD_REQUEST)

    try:
        body_size, body_file = await _read_request_body(request)
    except ValueError as exc:
        return HTMLResponse(f'<h1>413 Payload Too Large</h1><p>{exc}</p>', status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    body_text = _read_body_text(body_file)

    client_ip = request.client.host if request.client else 'unknown'
    frequency = await _get_request_frequency(client_ip)
    await _increment_stat('proxy:request_count')

    # Sanitize path before logging to avoid storing raw input that may contain
    # script payloads which could later be rendered unsafely in the admin UI.
    sanitized_path = urllib.parse.quote(request.url.path, safe='/')
    features = {
        'timestamp': time.time(),
        'client_ip': client_ip,
        'method': request.method,
        'path': sanitized_path,
        'query': request.url.query,
        'path_length': len(request.url.path),
        'header_count': len(request.headers),
        'body_size': body_size,
        'frequency': frequency,
        'user_agent': request.headers.get('user-agent', ''),
    }
    log_request_features(features)
    _append_event_log({'event': 'request', **features})
    _log_event(
        'proxy_request',
        request_id=getattr(request.state, 'request_id', None),
        method=request.method,
        path=request.url.path,
        client_ip=client_ip,
        status='accepted',
        body_size=body_size,
    )

    if config_manager.config.ml.get('enabled', False) and anomaly_model is not None:
        score = anomaly_model.score_request(features)
        if score is not None and anomaly_model.is_anomalous(score):
            await _increment_stat('proxy:anomaly_count')
            return HTMLResponse(
                f'<h1>403 Forbidden</h1><p>Request blocked by ML anomaly detector. Score={score:.4f}</p>',
                status_code=status.HTTP_403_FORBIDDEN,
            )

    if config_manager.config.waf.get('enabled', False):
        waf_result = scan_request_components(
            request.url.path,
            request.url.query,
            body_text,
            config_manager.config.waf['rules'],
            headers=dict(request.headers),
        )
        if waf_result:
            rule_name, _, details = waf_result
            _append_event_log({'event': 'waf_block', 'rule': rule_name, 'details': details, 'path': urllib.parse.quote(request.url.path, safe='/'), 'client_ip': client_ip})
            _log_event(
                'waf_block',
                request_id=getattr(request.state, 'request_id', None),
                rule=rule_name,
                details=details,
                path=request.url.path,
                client_ip=client_ip,
            )
            page = render_blocked_page(rule_name, details)
            return HTMLResponse(page, status_code=status.HTTP_403_FORBIDDEN)

    if config_manager.config.rate_limit.get('enabled', False):
        status_key, _ = await evaluate_request(redis_client, client_ip, config_manager.config.rate_limit)
        if status_key == 'block':
            return HTMLResponse(render_rate_limit_page('block'), status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        if status_key == 'grey':
            return HTMLResponse(render_rate_limit_page('grey'), status_code=status.HTTP_429_TOO_MANY_REQUESTS)

    proxy_headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
    content = None
    if request.method not in ('GET', 'HEAD', 'DELETE', 'OPTIONS'):
        content = TempFileByteStream(body_file)

    try:
        backend_request = app.state.client.build_request(request.method, backend_url, headers=proxy_headers, content=content)
        backend_response = await app.state.client.send(backend_request, stream=True)
    except RuntimeError as exc:
        if 'closed' in str(exc).lower():
            app.state.client = httpx.AsyncClient(timeout=None, follow_redirects=False)
            backend_request = app.state.client.build_request(request.method, backend_url, headers=proxy_headers, content=content)
            backend_response = await app.state.client.send(backend_request, stream=True)
        else:
            raise
    except httpx.HTTPError as exc:
        logger.exception('backend_request_failed', extra={'backend_url': backend_url, 'error': str(exc)})
        return HTMLResponse(f'<h1>502 Bad Gateway</h1><p>Upstream request failed: {exc}</p>', status_code=status.HTTP_502_BAD_GATEWAY)

    response_headers = {
        k: v
        for k, v in backend_response.headers.items()
        if k.lower() != 'transfer-encoding'
    }

    async def backend_stream():
        try:
            async for chunk in backend_response.aiter_raw():
                yield chunk
        finally:
            await backend_response.aclose()

    return StreamingResponse(
        backend_stream(),
        status_code=backend_response.status_code,
        headers=response_headers,
    )


@app.get('/health')
async def healthcheck() -> Response:
    return Response(content='ok', media_type='text/plain', status_code=status.HTTP_200_OK)


@app.get('/livez')
async def liveness() -> Response:
    return Response(content='live', media_type='text/plain', status_code=status.HTTP_200_OK)


@app.get('/readyz')
async def readiness() -> Response:
    if not getattr(app.state, 'runtime_initialized', False):
        return Response(content='not ready', media_type='text/plain', status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    return Response(content='ready', media_type='text/plain', status_code=status.HTTP_200_OK)


@app.get('/metrics')
async def metrics() -> Response:
    payload = {
        'service': 'proxy',
        'target_backend': config_manager.config.target_backend,
        'waf_enabled': config_manager.config.waf.get('enabled', False),
        'rate_limit_enabled': config_manager.config.rate_limit.get('enabled', False),
        'ml_enabled': config_manager.config.ml.get('enabled', False),
        'redis_available': redis_client is not None,
        'log_level': config_manager.config.observability.get('log_level', 'INFO'),
        'request_id_header': 'x-request-id',
    }
    return JSONResponse(payload)


@app.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
async def proxy(request: Request, path: str) -> Response:
    return await _proxy_request(request, path)


def _build_backend_ws_url(path: str, query_string: str | None = None, raw_path: bytes | str | None = None) -> str:
    target_base = config_manager.config.target_backend.rstrip('/')
    candidate_path = path.strip()
    if raw_path:
        raw_candidate = raw_path.decode('utf-8', 'surrogateescape') if isinstance(raw_path, (bytes, bytearray)) else str(raw_path)
        if raw_candidate.startswith('//'):
            raise ValueError('Blocked absolute URL target')
        raw_candidate = urllib.parse.unquote(raw_candidate)
        if raw_candidate.startswith('//'):
            raise ValueError('Blocked absolute URL target')
        if re.match(r'^/{2,}[a-zA-Z][a-zA-Z0-9+.-]*://', raw_candidate):
            raise ValueError('Blocked absolute URL target')
    if not candidate_path:
        candidate_path = '/'
    if candidate_path.startswith('//'):
        raise ValueError('Blocked absolute URL target')
    parsed_path = urllib.parse.urlsplit(candidate_path)
    if parsed_path.scheme or parsed_path.netloc:
        raise ValueError('Blocked absolute URL target')
    candidate_path = candidate_path.lstrip('/')
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', candidate_path):
        raise ValueError('Blocked absolute URL target')
    if target_base.startswith('https://'):
        ws_base = 'wss://' + target_base[len('https://'):]
    elif target_base.startswith('http://'):
        ws_base = 'ws://' + target_base[len('http://'):]
    else:
        ws_base = target_base
    ws_url = urllib.parse.urljoin(ws_base + '/', candidate_path)
    parsed_ws = urllib.parse.urlsplit(ws_url)
    allowlist = [item.strip() for item in config_manager.config.ssrf_allowlist if item and item.strip()]
    if allowlist and not _matches_allowlist(parsed_ws.hostname, allowlist):
        raise ValueError('Blocked absolute URL target')
    if query_string:
        ws_url = f'{ws_url}?{query_string}'
    return ws_url


@app.websocket('/ws/{full_path:path}')
async def websocket_proxy(full_path: str, websocket: WebSocket):
    query_string = websocket.scope.get('query_string', b'').decode('utf-8')
    try:
        backend_url = _build_backend_ws_url(full_path, query_string, websocket.scope.get('raw_path'))
    except ValueError:
        await websocket.close(code=1008)
        return
    await websocket.accept()

    async def forward_client_to_backend(ws):
        while True:
            message = await websocket.receive()
            if message['type'] == 'websocket.receive':
                if 'text' in message:
                    await ws.send(message['text'])
                elif 'bytes' in message:
                    await ws.send(message['bytes'])
            elif message['type'] == 'websocket.disconnect':
                break

    async def forward_backend_to_client(ws):
        try:
            async for message in ws:
                if isinstance(message, str):
                    await websocket.send_text(message)
                else:
                    await websocket.send_bytes(message)
        except websockets.ConnectionClosed:
            pass

    try:
        async with websockets.connect(backend_url) as backend_ws:
            await asyncio.gather(
                forward_client_to_backend(backend_ws),
                forward_backend_to_client(backend_ws),
            )
    except Exception:
        await websocket.close()

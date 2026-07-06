import asyncio
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

DEFAULT_CONFIG = {
    'target_backend': 'http://httpbin.org',
    'waf': {
        'enabled': True,
        'rules': {
            'sql_injection': True,
            'xss': True,
            'path_traversal': True,
        },
    },
    'rate_limit': {
        'enabled': False,
        'capacity': 20,
        'refill_rate': 1.0,
        'cost_per_request': 1,
        'block_threshold': 5,
        'suspicious_threshold': 10,
        'suspicious_score': 1,
        'block_duration_seconds': 300,
        'grace_requests': 2,
    },
    'ml': {
        'enabled': False,
        'anomaly_threshold': 0.0,
    },
    'admin': {
        'enabled': True,
        'default_refresh_seconds': 5,
    },
}


@dataclass
class ProxyConfig:
    target_backend: str
    waf: dict = field(default_factory=dict)
    rate_limit: dict = field(default_factory=dict)
    ml: dict = field(default_factory=dict)
    admin: dict = field(default_factory=dict)


class ConfigManager:
    def __init__(self, config_path: str, redis_url: str | None = None):
        self.config_path = Path(config_path)
        self.redis_url = redis_url
        self.redis: Redis | None = None
        self.config = ProxyConfig(**DEFAULT_CONFIG)
        self._sub_task: asyncio.Task | None = None

    async def initialize(self):
        if self.redis_url:
            self.redis = Redis.from_url(self.redis_url, decode_responses=True)
        self.reload_from_file()
        if self.redis:
            try:
                await self._load_runtime_overrides()
                self._sub_task = asyncio.create_task(self._watch_config_updates())
            except RedisConnectionError:
                logging.warning('Redis is unavailable, continuing without runtime config overrides.')
                self.redis = None

    def _apply_env_overrides(self, merged: dict) -> None:
        if os.getenv('PROXY_TARGET') or os.getenv('TARGET_BACKEND'):
            merged['target_backend'] = os.getenv('PROXY_TARGET') or os.getenv('TARGET_BACKEND')
        if os.getenv('WAF_ENABLED') is not None:
            merged['waf']['enabled'] = os.getenv('WAF_ENABLED', 'true').lower() in {'1', 'true', 'yes', 'on'}
        if os.getenv('RATE_LIMIT_ENABLED') is not None:
            merged['rate_limit']['enabled'] = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() in {'1', 'true', 'yes', 'on'}
        if os.getenv('ML_ENABLED') is not None:
            merged['ml']['enabled'] = os.getenv('ML_ENABLED', 'true').lower() in {'1', 'true', 'yes', 'on'}
        if os.getenv('ML_THRESHOLD') is not None:
            merged['ml']['anomaly_threshold'] = float(os.getenv('ML_THRESHOLD'))

    def reload_from_file(self):
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as handle:
                raw = yaml.safe_load(handle) or {}
        else:
            raw = {}
        merged = {**DEFAULT_CONFIG, **raw}
        merged['waf'] = {**DEFAULT_CONFIG['waf'], **raw.get('waf', {})}
        merged['waf']['rules'] = {**DEFAULT_CONFIG['waf']['rules'], **raw.get('waf', {}).get('rules', {})}
        merged['rate_limit'] = {**DEFAULT_CONFIG['rate_limit'], **raw.get('rate_limit', {})}
        merged['ml'] = {**DEFAULT_CONFIG['ml'], **raw.get('ml', {})}
        merged['admin'] = {**DEFAULT_CONFIG['admin'], **raw.get('admin', {})}
        self._apply_env_overrides(merged)
        self.config = ProxyConfig(**merged)

    async def _load_runtime_overrides(self):
        if not self.redis:
            return
        runtime = await self.redis.hgetall('proxy:config')
        if not runtime:
            return
        if runtime.get('target_backend'):
            self.config.target_backend = runtime['target_backend']
        if runtime.get('waf.enabled') is not None:
            self.config.waf['enabled'] = runtime['waf.enabled'] == 'True'
        for name in DEFAULT_CONFIG['waf']['rules']:
            value = runtime.get(f'waf.rules.{name}')
            if value is not None:
                self.config.waf['rules'][name] = value == 'True'
        if runtime.get('rate_limit.enabled') is not None:
            self.config.rate_limit['enabled'] = runtime['rate_limit.enabled'] == 'True'
        for key in DEFAULT_CONFIG['rate_limit']:
            if key in runtime:
                self.config.rate_limit[key] = type(DEFAULT_CONFIG['rate_limit'][key])(runtime[key])
        if runtime.get('ml.enabled') is not None:
            self.config.ml['enabled'] = runtime['ml.enabled'] == 'True'
        if runtime.get('ml.anomaly_threshold') is not None:
            self.config.ml['anomaly_threshold'] = float(runtime['ml.anomaly_threshold'])

    async def update_runtime_setting(self, key: str, value: Any) -> None:
        if not self.redis:
            return
        await self.redis.hset('proxy:config', key, str(value))
        await self.redis.publish('proxy:config_updates', key)

    async def _watch_config_updates(self):
        if not self.redis:
            return
        pubsub = self.redis.pubsub(ignore_subscribe_messages=True)
        await pubsub.subscribe('proxy:config_updates')
        try:
            async for message in pubsub.listen():
                if message is None:
                    continue
                self.reload_from_file()
                await self._load_runtime_overrides()
        finally:
            await pubsub.unsubscribe('proxy:config_updates')
            await pubsub.close()

    async def shutdown(self):
        if self._sub_task:
            self._sub_task.cancel()
        if self.redis:
            await self.redis.close()

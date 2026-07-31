import time
from typing import Any

from redis.asyncio import Redis

TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local tokens_key = key .. ':tokens'
local ts_key = key .. ':ts'
local block_key = key .. ':blocked_until'
local blocked_count_key = key .. ':blocked_count'
local suspicious_key = 'proxy:suspicious_ips'

local now = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill_rate = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local block_threshold = tonumber(ARGV[5])
local suspicious_threshold = tonumber(ARGV[6])
local suspicious_score = tonumber(ARGV[7])
local block_duration = tonumber(ARGV[8])
local grace_requests = tonumber(ARGV[9])

local blocked_until = tonumber(redis.call('get', block_key) or 0)
if blocked_until > now then
  return {'block', tostring(blocked_until)}
end

local tokens = tonumber(redis.call('get', tokens_key) or capacity)
local last_ts = tonumber(redis.call('get', ts_key) or now)
local elapsed = math.max(0, now - last_ts)
local refill = elapsed * refill_rate
tokens = math.min(capacity, tokens + refill)

if tokens >= cost then
  tokens = tokens - cost
  redis.call('set', tokens_key, tokens, 'EX', math.ceil(capacity / refill_rate * 2 + 60))
  redis.call('set', ts_key, now, 'EX', math.ceil(capacity / refill_rate * 2 + 60))
  return {'allow', tostring(tokens)}
end

local blocked_count = tonumber(redis.call('incr', blocked_count_key) or 0)
if blocked_count == 1 then
  redis.call('expire', blocked_count_key, block_duration)
end

if blocked_count >= block_threshold then
  local until_ts = now + block_duration
  redis.call('set', block_key, until_ts, 'EX', block_duration)
  redis.call('hset', suspicious_key, key, tostring(blocked_count))
  return {'block', tostring(until_ts)}
end

local score = tonumber(redis.call('hincrby', suspicious_key, key, suspicious_score) or 0)
redis.call('expire', suspicious_key, block_duration)
return {'grey', tostring(score)}
"""


def get_redis_client(redis_url: str) -> Redis:
    return Redis.from_url(redis_url, decode_responses=True)


def render_rate_limit_page(status: str) -> str:
    if status == 'block':
        return '<html><body><h1>429 Too Many Requests</h1><p>Your IP has been temporarily blocked. Please solve the challenge and try again.</p></body></html>'
    return '<html><body><h1>429 Too Many Requests</h1><p>Your IP looks suspicious and is temporarily greylisted. Please wait before retrying.</p></body></html>'


async def evaluate_request(redis: Redis, client_ip: str, config: dict) -> tuple[str, dict]:
    if not redis:
        return 'allow', {}
    now = time.time()
    try:
        result = await redis.eval(
            TOKEN_BUCKET_LUA,
            1,
            client_ip,
            now,
            config['capacity'],
            config['refill_rate'],
            config['cost_per_request'],
            config['block_threshold'],
            config['suspicious_threshold'],
            config['suspicious_score'],
            config['block_duration_seconds'],
            config['grace_requests'],
        )
    except Exception:
        return 'allow', {}
    status = result[0]
    value = result[1]
    return status, {'value': value}


async def get_blocked_ips(redis: Redis) -> list[dict[str, Any]]:
    if not redis:
        return []
    suspicious = await redis.hgetall('proxy:suspicious_ips')
    return [{'ip': ip, 'score': int(score)} for ip, score in suspicious.items()]


async def get_rate_limit_stats(redis: Redis) -> dict[str, Any]:
    if not redis:
        return {'suspicious_ips': 0, 'blocked_ips': 0}
    suspicious = await redis.hgetall('proxy:suspicious_ips')
    blocked_count = 0
    for key in await redis.keys('*:blocked_until'):
        blocked_until = await redis.get(key)
        if blocked_until and float(blocked_until) > time.time():
            blocked_count += 1
    return {'suspicious_ips': len(suspicious), 'blocked_ips': blocked_count}


async def get_blocked_status(redis: Redis, client_ip: str) -> bool:
    if not redis:
        return False
    blocked_until = await redis.get(f'{client_ip}:blocked_until')
    return blocked_until is not None and float(blocked_until) > time.time()

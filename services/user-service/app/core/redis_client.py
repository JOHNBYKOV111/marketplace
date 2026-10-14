import redis.asyncio as aioredis
from app.core.config import settings

_redis = None

async def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=False)
    return _redis

async def init_redis():
    await get_redis()

async def close_redis():
    global _redis
    if _redis:
        await _redis.close()
        _redis = None
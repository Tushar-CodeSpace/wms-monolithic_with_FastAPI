import redis.asyncio as aioredis
from app.config import settings

# Initialize async redis client
redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

class CacheRepository:
    async def blacklist_token(self, token_id: str, expire_seconds: int):
        """Stores the token ID in Redis with an automatic expiration time."""
        await redis_client.setex(
            name=f"blacklist:{token_id}",
            time=expire_seconds,
            value="true"
        )

    async def is_token_blacklisted(self, token_id: str) -> bool:
        """Checks if the token ID exists in the blacklist."""
        exists = await redis_client.exists(f"blacklist:{token_id}")
        return exists > 0
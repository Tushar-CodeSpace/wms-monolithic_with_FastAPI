from datetime import datetime, timezone

class MemoryCacheRepository:
    def __init__(self):
        self._blacklist = {}

    def _cleanup_expired(self):
        # Internal helper to remove stale tokens and prevent memory leaks
        now = datetime.now(timezone.utc).timestamp()
        # Find all keys that have already expired
        expired_keys = [k for k, exp in self._blacklist.items() if now >= exp]
        for k in expired_keys:
            del self._blacklist[k]

    async def blacklist_token(self, token_id: str, expire_seconds: int):
        # Stores the token ID with its absolute expiration timestamp
        self._cleanup_expired()

        now = datetime.now(timezone.utc).timestamp()
        absolute_expiry = now + expire_seconds
        
        # Store it in memory
        self._blacklist[token_id] = absolute_expiry

    async def is_token_blacklisted(self, token_id: str) -> bool:
        # Checks if the token ID exists and hasn't expired yet.
        self._cleanup_expired()
        
        if token_id in self._blacklist:
            now = datetime.now(timezone.utc).timestamp()
            # If it's in the dictionary and hasn't expired, it is blacklisted
            if now < self._blacklist[token_id]:
                return True
        return False

# Instantiate a single global instance of this cache (Singleton Pattern)
cache_repository = MemoryCacheRepository()
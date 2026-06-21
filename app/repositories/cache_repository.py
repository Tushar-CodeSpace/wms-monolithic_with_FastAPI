from datetime import datetime, timezone

class MemoryCacheRepository:
    def __init__(self):
        self._blacklist = {}

    def _cleanup_expired(self):
        """Removes stale tokens from RAM to prevent memory leak degradation."""
        now = datetime.now(timezone.utc).timestamp()
        expired_keys = [k for k, exp in self._blacklist.items() if now >= exp]
        for k in expired_keys:
            del self._blacklist[k]

    async def blacklist_token(self, token_id: str, expire_seconds: int):
        """Stores token identifiers linked to absolute epoch deadlines."""
        self._cleanup_expired()
        now = datetime.now(timezone.utc).timestamp()
        self._blacklist[token_id] = now + expire_seconds

    async def is_token_blacklisted(self, token_id: str) -> bool:
        """Evaluates whether the token is blocked or dead."""
        self._cleanup_expired()
        if token_id in self._blacklist:
            now = datetime.now(timezone.utc).timestamp()
            if now < self._blacklist[token_id]:
                return True
        return False

# Single global instance shared across all requests
cache_repository = MemoryCacheRepository()
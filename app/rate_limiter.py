# app/rate_limiter.py - Redis Rate Limiting
import redis.asyncio as redis
from typing import Tuple
import os

class RateLimiter:
    """Redis-based rate limiter"""
    
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = None
        self.default_limit = int(os.getenv("RATE_LIMIT_REQUESTS", 100))
        self.default_period = int(os.getenv("RATE_LIMIT_PERIOD", 60))
    
    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis_client = await redis.from_url(self.redis_url, decode_responses=True)
            await self.redis_client.ping()
            print("✅ Redis connected for rate limiting")
            return self
        except Exception as e:
            print(f"⚠️ Redis not available: {e}. Rate limiting disabled.")
            self.redis_client = None
            return self
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis_client:
            await self.redis_client.close()
    
    async def check_rate_limit(self, user_id: str, limit: int = None, period: int = None) -> Tuple[bool, int]:
        """
        Check if user has exceeded rate limit.
        Returns: (is_allowed, remaining_requests)
        """
        if not self.redis_client:
            return True, 999  # Allow if Redis not available
        
        limit = limit or self.default_limit
        period = period or self.default_period
        
        key = f"rate_limit:{user_id}"
        
        current = await self.redis_client.get(key)
        
        if current and int(current) >= limit:
            return False, 0
        
        pipe = self.redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, period)
        await pipe.execute()
        
        remaining = limit - (int(current) + 1) if current else limit - 1
        return True, remaining
    
    async def get_user_stats(self, user_id: str) -> dict:
        """Get rate limit stats for a user"""
        if not self.redis_client:
            return {"requests": 0, "remaining": self.default_limit, "enabled": False}
        
        key = f"rate_limit:{user_id}"
        current = await self.redis_client.get(key)
        ttl = await self.redis_client.ttl(key)
        
        return {
            "requests": int(current) if current else 0,
            "remaining": self.default_limit - (int(current) if current else 0),
            "reset_in_seconds": ttl if ttl > 0 else 0,
            "enabled": True
        }
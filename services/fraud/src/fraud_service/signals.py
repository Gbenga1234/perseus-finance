"""Behavioural signals (velocity, daily volume, payee history) kept in Redis."""

from __future__ import annotations

import uuid
from typing import Protocol

from redis.asyncio import Redis

DAY_SECONDS = 86_400


class SignalStore(Protocol):
    async def record_attempt(self, user_id: str, now: float, window_seconds: int) -> int: ...
    async def daily_total(self, user_id: str, day: str) -> int: ...
    async def is_known_payee(self, user_id: str, account_id: str) -> bool: ...
    async def record_accepted(
        self, user_id: str, day: str, amount_minor: int, account_id: str
    ) -> None: ...


class RedisSignalStore:
    def __init__(self, redis: Redis, prefix: str = "fraud") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, *parts: str) -> str:
        return ":".join((self._prefix, *parts))

    async def record_attempt(self, user_id: str, now: float, window_seconds: int) -> int:
        key = self._key("velocity", user_id)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            pipe.zadd(key, {uuid.uuid4().hex: now})
            pipe.zcard(key)
            pipe.expire(key, window_seconds)
            results = await pipe.execute()
        return int(results[2])

    async def daily_total(self, user_id: str, day: str) -> int:
        value = await self._redis.get(self._key("daily", user_id, day))
        return int(value or 0)

    async def is_known_payee(self, user_id: str, account_id: str) -> bool:
        return bool(await self._redis.sismember(self._key("payees", user_id), account_id))

    async def record_accepted(
        self, user_id: str, day: str, amount_minor: int, account_id: str
    ) -> None:
        daily = self._key("daily", user_id, day)
        payees = self._key("payees", user_id)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incrby(daily, amount_minor)
            pipe.expire(daily, 2 * DAY_SECONDS)
            pipe.sadd(payees, account_id)
            pipe.expire(payees, 365 * DAY_SECONDS)
            await pipe.execute()


class InMemorySignalStore:
    """Test double with the same semantics as the Redis store."""

    def __init__(self) -> None:
        self.attempts: dict[str, list[float]] = {}
        self.daily: dict[tuple[str, str], int] = {}
        self.payees: dict[str, set[str]] = {}

    async def record_attempt(self, user_id: str, now: float, window_seconds: int) -> int:
        recent = [t for t in self.attempts.get(user_id, []) if t > now - window_seconds]
        recent.append(now)
        self.attempts[user_id] = recent
        return len(recent)

    async def daily_total(self, user_id: str, day: str) -> int:
        return self.daily.get((user_id, day), 0)

    async def is_known_payee(self, user_id: str, account_id: str) -> bool:
        return account_id in self.payees.get(user_id, set())

    async def record_accepted(
        self, user_id: str, day: str, amount_minor: int, account_id: str
    ) -> None:
        self.daily[(user_id, day)] = self.daily.get((user_id, day), 0) + amount_minor
        self.payees.setdefault(user_id, set()).add(account_id)

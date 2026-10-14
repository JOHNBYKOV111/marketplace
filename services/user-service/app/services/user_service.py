"""
User service for business logic operations.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional, Tuple, List
from uuid import UUID

from app.core.circuit_breaker import CircuitBreakerOpenError
from app.core.config import settings
from app.core.exceptions import ConflictException, NotFoundException
from app.core.http_client import AuthServiceHttpClient, AuthServiceError, AuthServiceUnavailableError
from app.core.logging import get_logger
from app.models.user import User
from app.models.audit_log import AuditLog

logger = get_logger(__name__)

# Cache TTL in seconds for successful auth-service responses
_USER_INFO_CACHE_TTL = 300  # 5 minutes

# Cache stampede lock TTL — max time a waiter blocks before re-checking cache
_CACHE_LOCK_TTL = 5.0  # seconds


class UserService:
    """Service for user-related business logic."""

    def __init__(
        self,
        db=None,
        redis_client=None,
        kafka_producer=None,
        user_repo=None,
        audit_repo=None,
        http_client: AuthServiceHttpClient | None = None,
    ):
        self.db = db
        self._redis_client = redis_client
        self._kafka_producer = kafka_producer
        self.user_repo = user_repo
        self.audit_repo = audit_repo
        self._http_client = http_client
        # Per-user locks for cache stampede prevention.
        self._cache_locks: dict[str, asyncio.Lock] = {}
        self._cache_locks_cleanup_counter: int = 0

    # ==================== AUTH SERVICE CALLS ====================

    async def _fetch_user_info_from_auth(self, user_id: UUID) -> dict:
        """Fetch user existence and status from auth-service with Redis caching.

        Cache strategy:
            - If circuit breaker is OPEN, return fallback immediately.
            - Successful responses cached for _USER_INFO_CACHE_TTL seconds.
            - Fallbacks are NEVER cached — prevents cache poisoning.
            - Cache stampede protection: only one concurrent request per user
              hits auth-service; others wait for the cache to populate.
        """
        if not self._http_client:
            logger.warning("No HTTP client configured, returning default user info")
            return self._default_user_info(user_id)

        # If circuit breaker is OPEN, skip cache and auth — fast-fail with fallback
        if hasattr(self._http_client, "_circuit_breaker") and self._http_client._circuit_breaker.is_open:
            return self._default_user_info(user_id)

        # Try Redis cache first — fast path
        cached = await self._get_cached_user_info(user_id)
        if cached is not None:
            # Ignore cached fallbacks — they are never stored, but safety check
            if not cached.get("email", "").endswith("@unknown.com"):
                return cached

        # Cache miss — acquire per-user lock to prevent stampede
        user_key = str(user_id)
        lock = self._get_or_create_cache_lock(user_key)

        try:
            await asyncio.wait_for(lock.acquire(), timeout=_CACHE_LOCK_TTL)
        except asyncio.TimeoutError:
            logger.warning(
                f"Cache lock timeout for user {user_id}, "
                f"proceeding without stampede protection"
            )

        try:
            # Double-check cache after acquiring lock
            cached = await self._get_cached_user_info(user_id)
            if cached is not None and not cached.get("email", "").endswith("@unknown.com"):
                return cached

            # Fetch from auth-service — only one coroutine reaches here
            try:
                data = await self._http_client.get_user_exists(user_id)
                if data.get("exists"):
                    info = {
                        "email": data.get("email", f"{user_id}@unknown.com"),
                        "is_active": data.get("is_active", True),
                        "is_email_verified": data.get("is_email_verified", False),
                    }
                    # Cache ONLY successful responses. Fallbacks are NEVER cached.
                    if not info["email"].endswith("@unknown.com"):
                        await self._set_cached_user_info(user_id, info)
                    return info
            except AuthServiceUnavailableError as e:
                logger.warning(
                    f"Auth-service unavailable (circuit open), "
                    f"using defaults for user {user_id}: {e}"
                )
            except AuthServiceError as e:
                logger.error(
                    f"Auth-service error fetching user info for {user_id}: {e}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error fetching user info for {user_id}: {e}"
                )

            return self._default_user_info(user_id)

        finally:
            if lock.locked():
                lock.release()
            self._maybe_cleanup_cache_locks()

    def _get_or_create_cache_lock(self, user_key: str) -> asyncio.Lock:
        """Get or create a per-user lock for cache stampede prevention."""
        if user_key not in self._cache_locks:
            self._cache_locks[user_key] = asyncio.Lock()
        return self._cache_locks[user_key]

    def _maybe_cleanup_cache_locks(self) -> None:
        """Periodically remove unused locks as a non-blocking background task."""
        self._cache_locks_cleanup_counter += 1
        if self._cache_locks_cleanup_counter >= 1000:
            self._cache_locks_cleanup_counter = 0
            
            async def _bg_cleanup():
                self._cache_locks = {
                    k: v for k, v in self._cache_locks.items()
                    if v.locked()
                }
            asyncio.create_task(_bg_cleanup())

    async def _get_cached_user_info(self, user_id: UUID) -> Optional[dict]:
        """Get cached user info from Redis. Returns None on miss or error."""
        if not self._redis_client:
            return None
        try:
            key = f"auth:user:{user_id}"
            data = await self._redis_client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception:
            return None

    async def _set_cached_user_info(self, user_id: UUID, info: dict) -> None:
        """Cache user info in Redis with TTL. Fails silently on error."""
        if not self._redis_client:
            return
        try:
            key = f"auth:user:{user_id}"
            await self._redis_client.set(key, json.dumps(info), ex=_USER_INFO_CACHE_TTL)
        except Exception:
            pass

    async def _notify_auth_delete_user(self, user_id: UUID) -> None:
        """Notify auth-service about user deletion. Fire-and-forget — failures are logged only."""
        if not self._http_client:
            return
        try:
            await self._http_client.delete_user_in_auth(user_id)
            await self._invalidate_user_info_cache(user_id)
        except AuthServiceUnavailableError as e:
            logger.warning(f"Auth-service unavailable for delete notification for user {user_id}: {e}")
        except AuthServiceError as e:
            logger.error(f"Auth-service failed to process delete for user {user_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error notifying auth-service about deletion of user {user_id}: {e}")

    async def _notify_auth_block_user(self, user_id: UUID, reason: str = "") -> None:
        """Notify auth-service about user block. Fire-and-forget — failures are logged only."""
        if not self._http_client:
            return
        try:
            await self._http_client.block_user_in_auth(user_id, reason)
            await self._invalidate_user_info_cache(user_id)
        except AuthServiceUnavailableError as e:
            logger.warning(f"Auth-service unavailable for block notification for user {user_id}: {e}")
        except AuthServiceError as e:
            logger.error(f"Auth-service failed to process block for user {user_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error notifying auth-service about block of user {user_id}: {e}")

    async def _notify_auth_unblock_user(self, user_id: UUID, reason: str = "") -> None:
        """Notify auth-service about user unblock. Fire-and-forget — failures are logged only."""
        if not self._http_client:
            return
        try:
            await self._http_client.unblock_user_in_auth(user_id, reason)
            await self._invalidate_user_info_cache(user_id)
        except AuthServiceUnavailableError as e:
            logger.warning(f"Auth-service unavailable for unblock notification for user {user_id}: {e}")
        except AuthServiceError as e:
            logger.error(f"Auth-service failed to process unblock for user {user_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error notifying auth-service about unblock of user {user_id}: {e}")

    async def _invalidate_user_info_cache(self, user_id: UUID) -> None:
        """Invalidate cached user info in Redis. Fails silently on error."""
        if not self._redis_client:
            return
        try:
            await self._redis_client.delete(f"auth:user:{user_id}")
        except Exception:
            pass

    @staticmethod
    def _default_user_info(user_id: UUID) -> dict:
        return {
            "email": f"{user_id}@unknown.com",
            "is_active": True,
            "is_email_verified": False,
        }

    # ==================== USER CRUD ====================

    async def create_user(
        self,
        user_id: UUID,
        email: str,
        phone: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> User:
        email_hash = User.create_email_hash(email)
        existing = await self.user_repo.get_by_email_hash(email_hash)
        if existing:
            raise ConflictException(f"User with email {email} already exists")

        if phone:
            phone_hash = User.create_phone_hash(phone)
            existing_phone = await self.user_repo.get_by_phone_hash(phone_hash)
            if existing_phone:
                raise ConflictException(f"User with phone {phone} already exists")

        user = User(
            id=user_id,
            email_hash=email_hash,
            first_name=first_name,
            last_name=last_name,
        )
        if phone:
            user.phone_hash = User.create_phone_hash(phone)

        created = await self.user_repo.create(user)
        await self.db.commit()

        try:
            await self._publish_user_registered(user_id, email)
        except Exception:
            pass

        return created

    async def get_user_by_id(self, user_id: UUID):
        if self._redis_client:
            try:
                key = f"user:{user_id}"
                data = await self._redis_client.get(key)
                if data:
                    return json.loads(data)
            except Exception:
                pass
        return await self.user_repo.get_by_id(user_id)

    async def ensure_user_exists(self, user_id: UUID) -> User:
        user = await self.get_user_by_id(user_id)
        if user:
            return user

        info = await self._fetch_user_info_from_auth(user_id)
        user = User(
            id=user_id,
            email_hash=User.create_email_hash(info["email"]),
        )
        await self.user_repo.create(user)
        await self.db.commit()
        return user

    async def get_user_by_email(self, email: str):
        email_hash = User.create_email_hash(email)
        return await self.user_repo.get_by_email_hash(email_hash)

    async def get_user_by_phone(self, phone: str):
        phone_hash = User.create_phone_hash(phone)
        return await self.user_repo.get_by_phone_hash(phone_hash)

    async def update_user(self, user_id: UUID, **kwargs):
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundException(f"User {user_id} not found")

        for key, value in kwargs.items():
            if value is not None and hasattr(user, key):
                setattr(user, key, value)

        await self.db.commit()

        if self._redis_client:
            try:
                await self._redis_client.delete(f"user:{user_id}")
            except Exception:
                pass

        try:
            await self._publish_user_updated(user_id, kwargs)
        except Exception:
            pass

        return user

    async def delete_user(self, user_id: UUID) -> bool:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundException(f"User {user_id} not found")

        if user.is_deleted:
            return True

        user.is_deleted = True
        user.deleted_at = datetime.now(timezone.utc)
        await self.db.commit()

        if self._redis_client:
            try:
                await self._redis_client.delete(f"user:{user_id}")
            except Exception:
                pass

        await self._notify_auth_delete_user(user_id)

        try:
            await self._publish_user_deleted(user_id)
        except Exception:
            pass

        return True

    async def change_password(self, user_id: UUID, current_password: str, new_password: str) -> bool:
        raise NotImplementedError("Password management is in auth-service only")

    async def get_sessions(self, user_id: UUID) -> list:
        return []

    async def hard_delete_expired_users(self) -> int:
        count = await self.user_repo.delete_expired_soft_deleted()
        await self.db.commit()
        return count

    async def block_user(self, user_id: UUID, reason: Optional[str] = None) -> bool:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundException(f"User {user_id} not found")

        if self.audit_repo:
            try:
                await self.audit_repo.create(AuditLog(
                    user_id=user_id,
                    action="block_user",
                    success=True,
                    details={"reason": reason or ""},
                ))
            except Exception:
                pass

        await self._notify_auth_block_user(user_id, reason or "")
        return True

    async def unblock_user(self, user_id: UUID, reason: Optional[str] = None) -> bool:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundException(f"User {user_id} not found")

        if self.audit_repo:
            try:
                await self.audit_repo.create(AuditLog(
                    user_id=user_id,
                    action="unblock_user",
                    success=True,
                    details={"reason": reason or ""},
                ))
            except Exception:
                pass

        await self._notify_auth_unblock_user(user_id, reason or "")
        return True

    async def verify_email(self, user_id: UUID) -> bool:
        return False

    async def verify_phone(self, user_id: UUID) -> bool:
        return True

    async def get_active_sessions_count(self, user_id: UUID) -> int:
        return 0

    async def list_users(
        self,
        limit: int = 20,
        offset: int = 0,
        search: str = None,
    ) -> Tuple[List[User], int]:
        return await self.user_repo.list_users(
            limit=limit,
            offset=offset,
            search=search,
        )

    async def get_audit_logs(
        self,
        user_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[AuditLog], int]:
        if self.audit_repo:
            return await self.audit_repo.get_by_user_id(
                user_id=user_id,
                limit=limit,
                offset=offset,
            )
        return [], 0

    # ==================== KAFKA PUBLISHERS ====================

    async def _publish_user_registered(self, user_id: UUID, email: str):
        if self._kafka_producer:
            await self._kafka_producer.send(
                "user.registered",
                value={"user_id": str(user_id), "email": email, "event_type": "user.registered"},
                key=str(user_id),
            )

    async def _publish_user_deleted(self, user_id: UUID):
        if self._kafka_producer:
            await self._kafka_producer.send(
                "user.deleted",
                value={"user_id": str(user_id), "event_type": "user.deleted"},
                key=str(user_id),
            )

    async def _publish_user_updated(self, user_id: UUID, changes: dict):
        if self._kafka_producer:
            await self._kafka_producer.send(
                "user.updated",
                value={"user_id": str(user_id), "changes": changes, "event_type": "user.updated"},
                key=str(user_id),
            )

    async def _publish_user_blocked(self, user_id: UUID, reason: str):
        if self._kafka_producer:
            await self._kafka_producer.send(
                "user.blocked",
                value={"user_id": str(user_id), "reason": reason, "event_type": "user.blocked"},
                key=str(user_id),
            )

    async def _publish_user_unblocked(self, user_id: UUID, reason: str):
        if self._kafka_producer:
            await self._kafka_producer.send(
                "user.unblocked",
                value={"user_id": str(user_id), "reason": reason, "event_type": "user.unblocked"},
                key=str(user_id),
            )

    async def _publish_email_verified(self, user_id: UUID, email_hash: str):
        if self._kafka_producer:
            await self._kafka_producer.send(
                "user.email.verified",
                value={"user_id": str(user_id), "email_hash": email_hash, "event_type": "user.email.verified"},
                key=str(user_id),
            )
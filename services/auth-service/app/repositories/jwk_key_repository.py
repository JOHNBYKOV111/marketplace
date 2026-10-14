"""
Репозиторий для работы с JWK (JSON Web Key) ключами.

Обеспечивает:
- CRUD операции для JWK ключей
- Фильтрацию активных/неактивных/истекших ключей
- Атомарные операции активации/деактивации
- Очистку истекших ключей
- Подсчеты и метрики
- Полную совместимость с SQLAlchemy 2.0 и asyncpg

Связанные модули:
- app.models.jwk_key - модель JWKKey
- app.services.jwk_service - бизнес-логика работы с ключами
- app.core.security - подпись и верификация JWT
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.jwk_key import JWKKey
from app.repositories.base import BaseRepository


class JWKKeyRepository(BaseRepository[JWKKey]):
    """Репозиторий для управления JWK ключами в БД."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(JWKKey, session)
        self._session = session

    async def create(self, key: JWKKey) -> JWKKey:
        self._session.add(key)
        await self._session.flush()
        await self._session.refresh(key)
        return key

    async def get_by_kid(self, kid: str) -> Optional[JWKKey]:
        stmt = select(JWKKey).where(JWKKey.kid == kid)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id(self, key_id: UUID) -> Optional[JWKKey]:
        return await self.get(key_id)

    def _active_conditions(self):
        """Условия для активного (не истекшего) ключа."""
        now = datetime.now(timezone.utc)
        return and_(
            JWKKey.is_active == True,
            JWKKey.expires_at.is_(None) | (JWKKey.expires_at > now),
        )

    async def get_active_keys(self) -> List[JWKKey]:
        stmt = (
            select(JWKKey)
            .where(self._active_conditions())
            .order_by(JWKKey.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_all_keys(self) -> List[JWKKey]:
        stmt = select(JWKKey).order_by(JWKKey.created_at.desc())
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_expired_keys(self) -> List[JWKKey]:
        now = datetime.now(timezone.utc)
        stmt = select(JWKKey).where(JWKKey.expires_at < now)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_active_key_by_algorithm(self, algorithm: str) -> Optional[JWKKey]:
        stmt = (
            select(JWKKey)
            .where(
                and_(
                    self._active_conditions(),
                    JWKKey.algorithm == algorithm,
                )
            )
            .order_by(JWKKey.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_primary_key(self) -> Optional[JWKKey]:
        stmt = (
            select(JWKKey)
            .where(self._active_conditions())
            .order_by(JWKKey.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_keys_for_verification(self) -> List[JWKKey]:
        stmt = (
            select(JWKKey)
            .where(
                and_(
                    JWKKey.is_verification_enabled == True,
                    self._active_conditions(),
                )
            )
            .order_by(JWKKey.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count_active_keys(self) -> int:
        stmt = (
            select(func.count())
            .select_from(JWKKey)
            .where(self._active_conditions())
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_expired_keys(self) -> int:
        now = datetime.now(timezone.utc)
        stmt = (
            select(func.count())
            .select_from(JWKKey)
            .where(JWKKey.expires_at < now)
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_total_keys(self) -> int:
        stmt = select(func.count()).select_from(JWKKey)
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_keys_by_algorithm(self) -> Dict[str, int]:
        stmt = select(JWKKey.algorithm, func.count()).group_by(JWKKey.algorithm)
        result = await self._session.execute(stmt)
        return dict(result.all())

    async def get_key_metrics(self) -> tuple:
        active = await self.count_active_keys()
        expired = await self.count_expired_keys()
        total = await self.count_total_keys()
        return active, expired, total

    async def activate_key(self, kid: str, activated_by: Optional[str] = None) -> bool:
        now = datetime.now(timezone.utc)
        values = {
            "is_active": True,
            "activated_at": now,
            "updated_at": now,
        }
        if activated_by:
            values["activated_by"] = activated_by

        stmt = (
            update(JWKKey)
            .where(JWKKey.kid == kid)
            .values(**values)
            .returning(JWKKey.id)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar() is not None

    async def deactivate_key(self, kid: str) -> bool:
        now = datetime.now(timezone.utc)
        stmt = (
            update(JWKKey)
            .where(JWKKey.kid == kid)
            .values(is_active=False, updated_at=now)
            .returning(JWKKey.id)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar() is not None

    async def expire_key(self, kid: str) -> bool:
        now = datetime.now(timezone.utc)
        stmt = (
            update(JWKKey)
            .where(JWKKey.kid == kid)
            .values(is_active=False, expires_at=now, updated_at=now)
            .returning(JWKKey.id)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar() is not None

    async def update_key(self, kid: str, **kwargs) -> Optional[JWKKey]:
        kwargs["updated_at"] = datetime.now(timezone.utc)
        stmt = (
            update(JWKKey)
            .where(JWKKey.kid == kid)
            .values(**kwargs)
            .returning(JWKKey)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar_one_or_none()

    async def delete_expired_keys(self) -> int:
        now = datetime.now(timezone.utc)
        stmt = delete(JWKKey).where(JWKKey.expires_at < now)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_key_by_kid(self, kid: str) -> bool:
        stmt = delete(JWKKey).where(JWKKey.kid == kid)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount > 0

    async def delete_old_keys(self, keep_count: int = 2) -> int:
        stmt = select(JWKKey.id).order_by(JWKKey.created_at.desc()).limit(keep_count)
        result = await self._session.execute(stmt)
        keep_ids = [row[0] for row in result.all()]
        if not keep_ids:
            return 0
        stmt = delete(JWKKey).where(JWKKey.id.not_in(keep_ids))
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def rotate_primary_key(
        self, new_kid: str, new_private_key_encrypted: str, new_public_key: str,
        algorithm: str, key_type: str, expires_at: Optional[datetime] = None,
        created_by: Optional[str] = None,
    ) -> JWKKey:
        new_key = JWKKey(
            kid=new_kid, private_key_encrypted=new_private_key_encrypted,
            public_key=new_public_key, algorithm=algorithm, key_type=key_type,
            is_active=True, is_verification_enabled=True,
            expires_at=expires_at, created_by=created_by,
            activated_at=datetime.now(timezone.utc),
        )
        await self.create(new_key)
        active_keys = await self.get_active_keys()
        for key in active_keys:
            if key.kid != new_kid:
                await self.deactivate_key(key.kid)
        return new_key

    async def key_exists(self, kid: str) -> bool:
        stmt = select(JWKKey.id).where(JWKKey.kid == kid).limit(1)
        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def is_key_active(self, kid: str) -> bool:
        key = await self.get_by_kid(kid)
        if key is None:
            return False
        return key.is_valid

    async def get_expired_keys_count(self) -> int:
        return await self.count_expired_keys()
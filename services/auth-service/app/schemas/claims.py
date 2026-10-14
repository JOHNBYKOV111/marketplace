"""
Схемы для Claims (утверждений) пользователя.

Содержит Pydantic-схемы для работы с данными пользователя,
извлеченными из заголовков Gateway или JWT токенов.

Обеспечивает:
- Типизированное представление данных пользователя
- Валидацию входящих данных
- Сериализацию для ответов
- Единый контракт для всего приложения
"""

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class CurrentUserClaims(BaseModel):
    """
    Утверждения (claims) текущего аутентифицированного пользователя.
    
    Содержит информацию о пользователе, полученную от Gateway
    или извлеченную из JWT токена.
    
    Attributes:
        user_id: Уникальный идентификатор пользователя (UUID)
        roles: Список ролей пользователя (admin, user, moderator, etc.)
        email: Email пользователя (опционально)
        name: Имя пользователя (опционально)
        session_id: Идентификатор сессии (опционально)
        client_type: Тип клиента (web, mobile, api, admin)
        client_version: Версия клиента
    """
    
    user_id: UUID = Field(
        ...,
        description="Уникальный идентификатор пользователя",
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )
    
    roles: List[str] = Field(
        default_factory=list,
        description="Список ролей пользователя",
        examples=[["admin", "user"]],
    )
    
    email: Optional[str] = Field(
        default=None,
        description="Email пользователя",
        examples=["user@example.com"],
        max_length=255,
    )
    
    name: Optional[str] = Field(
        default=None,
        description="Имя пользователя",
        examples=["John Doe"],
        max_length=100,
    )
    
    session_id: Optional[str] = Field(
        default=None,
        description="Идентификатор сессии",
        examples=["sess_123e4567"],
    )
    
    client_type: Optional[str] = Field(
        default="unknown",
        description="Тип клиента",
        examples=["web", "mobile", "api", "admin"],
        max_length=50,
    )
    
    client_version: Optional[str] = Field(
        default=None,
        description="Версия клиента",
        examples=["1.0.0", "2.1.3"],
        max_length=20,
    )
    
    @field_validator("roles")
    @classmethod
    def validate_roles(cls, v: List[str]) -> List[str]:
        """
        Валидация списка ролей.
        
        Args:
            v: Список ролей
            
        Returns:
            List[str]: Очищенный список ролей
            
        Raises:
            ValueError: Если роль содержит недопустимые символы
        """
        if not v:
            return []
        
        # Проверка что все роли в нижнем регистре и без пробелов
        cleaned = []
        for role in v:
            if not role or not isinstance(role, str):
                continue
            
            role_clean = role.strip().lower()
            if role_clean:
                # Проверка на допустимые символы (только буквы, цифры и подчеркивание)
                if not role_clean.replace("_", "").isalnum():
                    raise ValueError(f"Invalid role format: {role}")
                cleaned.append(role_clean)
        
        return cleaned
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        """
        Валидация email.
        
        Args:
            v: Email пользователя
            
        Returns:
            Optional[str]: Валидный email или None
        """
        if not v:
            return None
        
        # Базовая валидация email
        if "@" not in v or "." not in v:
            raise ValueError("Invalid email format")
        
        return v.strip().lower()
    
    def is_admin(self) -> bool:
        """
        Проверка, является ли пользователь администратором.
        
        Returns:
            bool: True если пользователь имеет роль admin
        """
        return "admin" in self.roles
    
    def is_superuser(self) -> bool:
        """
        Проверка, является ли пользователь суперпользователем.
        
        Returns:
            bool: True если пользователь имеет роль superuser
        """
        return "superuser" in self.roles
    
    def has_role(self, role: str) -> bool:
        """
        Проверка наличия конкретной роли.
        
        Args:
            role: Роль для проверки
            
        Returns:
            bool: True если пользователь имеет указанную роль
        """
        return role.strip().lower() in self.roles
    
    def has_any_role(self, roles: List[str]) -> bool:
        """
        Проверка наличия хотя бы одной роли из списка.
        
        Args:
            roles: Список ролей для проверки
            
        Returns:
            bool: True если пользователь имеет хотя бы одну из ролей
        """
        if not roles:
            return True
        
        normalized = [r.strip().lower() for r in roles if r]
        return any(role in self.roles for role in normalized)
    
    def has_all_roles(self, roles: List[str]) -> bool:
        """
        Проверка наличия всех ролей из списка.
        
        Args:
            roles: Список ролей для проверки
            
        Returns:
            bool: True если пользователь имеет все указанные роли
        """
        if not roles:
            return True
        
        normalized = [r.strip().lower() for r in roles if r]
        return all(role in self.roles for role in normalized)
    
    class Config:
        """Конфигурация Pydantic модели."""
        
        # Использовать строчную нотацию для полей
        alias_generator = lambda s: s
        
        # Запретить дополнительные поля
        extra = "forbid"
        
        # Пример для документации
        json_schema_extra = {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "roles": ["admin", "user"],
                "email": "user@example.com",
                "name": "John Doe",
                "session_id": "sess_123e4567",
                "client_type": "web",
                "client_version": "1.0.0",
            }
        }


class CurrentUserClaimsOptional(BaseModel):
    """
    Опциональные утверждения пользователя (для неавторизованных запросов).
    
    Используется в эндпоинтах, где пользователь может быть
    как авторизован, так и нет.
    """
    
    user_id: Optional[UUID] = Field(
        default=None,
        description="ID пользователя (если авторизован)",
    )
    
    roles: List[str] = Field(
        default_factory=list,
        description="Роли пользователя (пустой список если не авторизован)",
    )
    
    is_authenticated: bool = Field(
        default=False,
        description="Флаг авторизации",
    )
    
    @classmethod
    def from_claims(cls, claims: CurrentUserClaims) -> "CurrentUserClaimsOptional":
        """
        Создание опциональных утверждений из полных.
        
        Args:
            claims: Полные утверждения пользователя
            
        Returns:
            CurrentUserClaimsOptional: Опциональные утверждения
        """
        return cls(
            user_id=claims.user_id,
            roles=claims.roles,
            is_authenticated=True,
        )


__all__ = [
    "CurrentUserClaims",
    "CurrentUserClaimsOptional",
]
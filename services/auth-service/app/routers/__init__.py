"""
Роутеры приложения.
"""

from app.routers.admin import router as admin_router
from app.routers.health import router as health_router
from app.routers.auth import router as auth_router
from app.routers.user import router as user_router
from app.routers.security import router as security_router
from app.routers.internal import router as internal_router
from app.routers.jwks import router as jwks_router

__all__ = [
    "admin_router",
    "health_router",
    "auth_router",
    "user_router",
    "security_router",
    "internal_router",
    "jwks_router",
]
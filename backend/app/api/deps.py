from typing import Optional
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import ForbiddenException, UnauthorizedException
from app.core.security import decode_token
from app.models.user import User
from app.repositories.user_repository import UserRepository

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Retrieves current user from Bearer token if provided. Rejects invalid or expired tokens."""
    if not token:
        return None
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise UnauthorizedException("Malformed token payload.")
    except UnauthorizedException:
        raise
    except jwt.PyJWTError as e:
        raise UnauthorizedException(f"Invalid or expired authentication token: {str(e)}")
    except Exception as e:
        raise UnauthorizedException(f"Token verification failed: {str(e)}")

    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id) or user_repo.get_by_email(user_id)
    if not user:
        # Stateless token support with role claim
        role = payload.get("role")
        if role:
            user = User(
                id=user_id,
                email=payload.get("email") or user_id,
                full_name=payload.get("name") or "User",
                role=role,
                is_active=True
            )
        else:
            raise UnauthorizedException("User associated with token does not exist.")
    if not user.is_active:
        raise UnauthorizedException("Inactive user account.")
    return user


def require_authenticated_user(
    user: Optional[User] = Depends(get_current_user)
) -> User:
    """Enforces authentication for protected endpoints."""
    if not user:
        raise UnauthorizedException("Authentication credentials are required.")
    if not user.is_active:
        raise UnauthorizedException("Inactive user account.")
    return user


def require_role(allowed_roles: list[str]):
    """Enforces specific role membership for privileged operations. Roles: Admin, Security Analyst, Viewer."""
    def role_checker(user: User = Depends(require_authenticated_user)) -> User:
        user_role = user.role or "Security Analyst"
        normalized_allowed = [r.lower() for r in allowed_roles]
        if user_role.lower() not in normalized_allowed and "admin" not in user_role.lower():
            raise ForbiddenException(f"User role '{user_role}' lacks required permissions.")
        return user
    return role_checker


def require_role_or_demo(allowed_roles: list[str]):
    """
    Enforces RBAC role permissions if authenticated.
    Rejects unauthorized roles with 403 Forbidden.
    In production mode, requires authentication unconditionally.
    """
    def role_checker(user: Optional[User] = Depends(get_current_user)) -> Optional[User]:
        if settings.APP_ENV == "production" and not user:
            raise UnauthorizedException("Authentication credentials are required in production environment.")
        if user is not None:
            user_role = user.role or "Security Analyst"
            normalized_allowed = [r.lower() for r in allowed_roles]
            if user_role.lower() not in normalized_allowed and "admin" not in user_role.lower():
                raise ForbiddenException(f"User role '{user_role}' lacks required permissions.")
        return user
    return role_checker

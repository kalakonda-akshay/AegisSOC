from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.exceptions import BadRequestException, UnauthorizedException
from app.core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from app.models.user import Role, User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.user_repo = UserRepository(db)

    def authenticate(self, login_data: LoginRequest) -> TokenResponse:
        user = self.user_repo.get_by_email(login_data.email)
        if not user or not verify_password(login_data.password, user.hashed_password):
            raise UnauthorizedException("Invalid email or password.")
        if not user.is_active:
            raise UnauthorizedException("User account is inactive.")

        role_name = user.role or (user.role_rel.name if user.role_rel else "Security Analyst")
        access_token = create_access_token(
            subject=user.id,
            extra_claims={"email": user.email, "role": role_name}
        )
        refresh_token = create_refresh_token(subject=user.id)

        user_resp = UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=role_name,
            is_active=user.is_active
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user_resp
        )

    def register_user(self, user_create: UserCreate) -> UserResponse:
        existing = self.user_repo.get_by_email(user_create.email)
        if existing:
            raise BadRequestException("User with this email already exists.")

        # Defense against Privilege Escalation: Disallow self-registration as Admin
        requested_role = user_create.role_name.strip()
        if requested_role.lower() == "admin":
            raise BadRequestException(
                "Self-registration as Admin is strictly prohibited. Administrator accounts must be provisioned by existing administrators."
            )

        # Normalize role: default to Viewer if not Security Analyst
        normalized_role = "Security Analyst" if requested_role.lower() in ["analyst", "security analyst"] else "Viewer"

        role = self.user_repo.get_role_by_name(normalized_role)
        if not role:
            role = Role(name=normalized_role, description=f"{normalized_role} role")
            self.db.add(role)
            self.db.flush()

        user = User(
            email=user_create.email,
            hashed_password=hash_password(user_create.password),
            full_name=user_create.full_name,
            role=normalized_role,
            role_id=role.id if role else None,
            is_active=True
        )
        created_user = self.user_repo.create(user)
        self.db.commit()

        return UserResponse(
            id=created_user.id,
            email=created_user.email,
            full_name=created_user.full_name,
            role=created_user.role,
            is_active=created_user.is_active
        )

    def refresh_access_token(self, refresh_token_str: str) -> str:
        try:
            payload = decode_token(refresh_token_str)
            token_type = payload.get("type")
            if token_type != "refresh":
                raise UnauthorizedException("Invalid token type. A refresh token is required.")
            user_id = payload.get("sub")
            if not user_id:
                raise UnauthorizedException("Invalid refresh token payload.")
        except UnauthorizedException:
            raise
        except Exception:
            raise UnauthorizedException("Expired or invalid refresh token.")

        user = self.user_repo.get_by_id(user_id)
        if not user or not user.is_active:
            raise UnauthorizedException("User no longer valid.")

        role_name = user.role or (user.role_rel.name if user.role_rel else "Security Analyst")
        return create_access_token(
            subject=user.id,
            extra_claims={"email": user.email, "role": role_name}
        )

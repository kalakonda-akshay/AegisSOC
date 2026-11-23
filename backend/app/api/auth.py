from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.api.deps import get_db, require_authenticated_user
from app.core.rate_limiter import rate_limit
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshTokenRequest, TokenResponse, UserCreate, UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(rate_limit(max_requests=10, window_seconds=60))])
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """Authenticates an analyst and issues access and refresh JWT tokens."""
    service = AuthService(db)
    return service.authenticate(login_data)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit(max_requests=5, window_seconds=60))])
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """Registers a new SOC analyst or operator."""
    service = AuthService(db)
    return service.register_user(user_data)


@router.post("/refresh")
def refresh_token(
    refresh_req: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refreshes an expired access token using a valid refresh token."""
    service = AuthService(db)
    new_access_token = service.refresh_access_token(refresh_req.refresh_token)
    return {"access_token": new_access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(require_authenticated_user)
):
    """Returns profile information for the authenticated user."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role or "Security Analyst",
        is_active=current_user.is_active
    )

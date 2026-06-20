from fastapi import APIRouter, Depends, status, Response

from app.config import settings
from app.schemas.auth_schema import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from app.services.auth_service import AuthService

router = APIRouter()

def get_auth_service():
    return AuthService()

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse
    )
async def register_user(
    payload: RegisterRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    created_user = await auth_service.register(payload)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {created_user.token}",
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=True
    )
    return RegisterResponse(
        user_id=created_user.user_id,
        token=created_user.token
    )

@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=LoginResponse
)
async def login_user(
    payload: LoginRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    authenticated_user = await auth_service.login(payload)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {authenticated_user.token}",
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=True
    )
    return LoginResponse(
        user_id=authenticated_user.user_id,
        token=authenticated_user.token
    )    
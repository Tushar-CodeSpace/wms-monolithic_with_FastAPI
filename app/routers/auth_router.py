from fastapi import APIRouter, Depends, status, Request, Response, HTTPException

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

@router.post("/logout")
async def logout_user(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    token = None
    
    # 1. Try to get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        
    # 2. Try to get token from Cookie if header is not present
    if not token:
        token_cookie = request.cookies.get("access_token")
        if token_cookie:
            token = token_cookie.replace("Bearer ", "") if token_cookie.startswith("Bearer ") else token_cookie

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You are not logged in."
        )
    
    await auth_service.logout(token)

    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="lax",
        secure=True
    )
    return {"message": "Successfully logged out"}
    
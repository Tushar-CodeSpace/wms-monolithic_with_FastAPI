from fastapi import APIRouter, Depends, status, Request, Response, HTTPException
from app.config import settings
from app.schemas.auth_schema import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from app.services.auth_service import AuthService
from app.dependencies.auth_deps import get_current_user

router = APIRouter()

def get_auth_service():
    return AuthService()

@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=RegisterResponse)
async def register_user(
    payload: RegisterRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    created_user = await auth_service.register(payload)
    response.set_cookie(
        key="access_token", value=f"Bearer {created_user.token}", httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax", secure=True
    )
    return created_user

@router.post("/login", status_code=status.HTTP_200_OK, response_model=LoginResponse)
async def login_user(
    payload: LoginRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    login_response, refresh_token = await auth_service.login(payload)
    
    response.set_cookie(
        key="access_token",
        value=f"Bearer {login_response.token}",
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 
        samesite="lax",
        secure=True
    )
    # Set refresh token cookie
    response.set_cookie(
        key="refresh_token", value=refresh_token, httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60, samesite="lax", secure=True
    )
    
    return login_response

@router.post("/logout")
async def logout_user(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    token_cookie = request.cookies.get("access_token")
    if not token_cookie:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are not logged in.")
        
    token = token_cookie.replace("Bearer ", "") if token_cookie.startswith("Bearer ") else token_cookie
    await auth_service.logout(token)

    response.delete_cookie(key="access_token", httponly=True, samesite="lax", secure=True)
    return {"message": "Successfully logged out"}

# ─── EXAMPLE PROTECTED ROUTE ───
@router.get("/me")
async def get_protected_profile(
    current_user: dict = Depends(get_current_user)
):
    """Example route consuming your cache_repository system automatically"""
    return {"user_id": current_user.get("sub"), "msg": "Token verified against blacklist successfully!"}

@router.post("/refresh")
async def refresh_access_token(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    refresh_cookie = request.cookies.get("refresh_token")
    if not refresh_cookie:
        raise HTTPException(status_code=401, detail="Refresh credentials missing.")

    # Request clean tokens from the service layer
    new_access, new_refresh = await auth_service.refresh_session(refresh_cookie)

    # Re-apply cookies securely
    response.set_cookie(
        key="access_token", value=f"Bearer {new_access}", httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, samesite="lax", secure=True
    )
    response.set_cookie(
        key="refresh_token", value=new_refresh, httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60, samesite="lax", secure=True
    )

    return {"msg": "Token refreshed successfully"}
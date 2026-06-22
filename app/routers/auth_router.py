from typing import List
from fastapi import APIRouter, Depends, status, Request, Response, HTTPException
from app.config import settings
from app.schemas.auth_schema import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from app.schemas.user_schema import TeamSchema
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
    register_response, refresh_token = await auth_service.register(payload)
    response.set_cookie(
        key="access_token", value=f"Bearer {register_response.token}", httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax", secure=True
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token, httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        samesite="lax", secure=True
    )
    return register_response

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
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Retrieves full user profile from database."""
    user_id = current_user.get("sub")
    user = await auth_service.repository.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    
    return {
        "id": user["_id"],
        "name": user["name"],
        "email": user["email"],
        "roles": user.get("roles", ["user"]),
        "permissions": user.get("permissions", []),
        "teams": user.get("teams", []),
        "is_active": user.get("is_active", True),
        "is_account_verified": user.get("is_account_verified", False),
        "created_at": user.get("created_at")
    }

@router.get("/teams", response_model=List[TeamSchema])
async def get_user_teams(
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Retrieves user's teams from database."""
    user_id = current_user.get("sub")
    user = await auth_service.repository.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user.get("teams", [])

from pydantic import BaseModel, Field
import uuid

class CreateTeamRequest(BaseModel):
    name: str = Field(..., min_length=1)

@router.post("/teams", status_code=status.HTTP_201_CREATED, response_model=TeamSchema)
async def create_user_team(
    payload: CreateTeamRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Creates a new team and adds it to the user's teams list."""
    user_id = current_user.get("sub")
    
    # Generate new team structure
    team_uuid = str(uuid.uuid4())[:8]
    team_id = f"team-{team_uuid}"
    new_team = {
        "_id": team_id,
        "name": payload.name.strip(),
        "roles": ["Owner", "Lead"]
    }
    
    # Push the new team to the user's teams list in MongoDB
    success = await auth_service.repository.add_team(user_id, new_team)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    return new_team

from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
import jwt

class DirectAddMemberRequest(BaseModel):
    email: EmailStr
    roles: List[str] = Field(default=["Member"])

class GenerateInviteRequest(BaseModel):
    expire_duration_hours: int = Field(default=24, ge=1, le=168)

class AcceptInviteRequest(BaseModel):
    token: str

@router.post("/teams/{team_id}/members", status_code=status.HTTP_200_OK)
async def add_team_member(
    team_id: str,
    payload: DirectAddMemberRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Directly adds another user to the team. Only accessible by admins or managers."""
    # 1. Authorize current user (must be global admin/manager or have team-specific Owner/Lead/Manager/Admin role)
    user_id = current_user.get("sub")
    user = await auth_service.repository.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    user_roles = user.get("roles", [])
    is_global_admin = "admin" in user_roles or "manager" in user_roles
    
    # 2. Find the team and check the roles
    team_name = None
    team_roles = []
    for team in user.get("teams", []):
        if team["_id"] == team_id:
            team_name = team["name"]
            team_roles = team.get("roles", [])
            break
            
    if not team_name:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found in your profile.")
        
    is_team_admin = any(role in ["Owner", "Lead", "Manager", "Admin"] for role in team_roles)
    
    if not is_global_admin and not is_team_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You do not have permission to manage this team. Only Owners, Leads, Managers or global Administrators can add members."
        )
        
    # 3. Find target user by email
    target_user = await auth_service.repository.find_by_email(payload.email.lower().strip())
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
        
    # 4. Check if target user is already in the team
    target_teams = target_user.get("teams", [])
    if any(t["_id"] == team_id for t in target_teams):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already in this team.")
        
    # 5. Add team to target user
    added_team = {
        "_id": team_id,
        "name": team_name,
        "roles": payload.roles
    }
    await auth_service.repository.add_team(target_user["_id"], added_team)
    
    return {"message": f"Successfully added {payload.email} to team {team_name}."}

@router.post("/teams/{team_id}/invites", status_code=status.HTTP_200_OK)
async def generate_team_invite(
    team_id: str,
    payload: GenerateInviteRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Generates an invitation token for a team."""
    user_id = current_user.get("sub")
    user = await auth_service.repository.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    user_roles = user.get("roles", [])
    is_global_admin = "admin" in user_roles or "manager" in user_roles
    
    # Find the team and check the roles
    team_name = None
    team_roles = []
    for team in user.get("teams", []):
        if team["_id"] == team_id:
            team_name = team["name"]
            team_roles = team.get("roles", [])
            break
            
    if not team_name:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found in your profile.")
        
    is_team_admin = any(role in ["Owner", "Lead", "Manager", "Admin"] for role in team_roles)
    
    if not is_global_admin and not is_team_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You do not have permission to manage this team. Only Owners, Leads, Managers or global Administrators can invite members."
        )
        
    # Generate signed JWT token
    now = datetime.now(timezone.utc)
    jwt_payload = {
        "team_id": team_id,
        "team_name": team_name,
        "exp": now + timedelta(hours=payload.expire_duration_hours),
        "iat": now
    }
    invite_token = jwt.encode(jwt_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    
    return {"invite_token": invite_token}

@router.post("/invites/accept", status_code=status.HTTP_200_OK)
async def accept_team_invite(
    payload: AcceptInviteRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Accepts a team invite and adds the user to the team."""
    user_id = current_user.get("sub")
    user = await auth_service.repository.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    # Decode invitation token
    try:
        jwt_payload = jwt.decode(payload.token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invitation link has expired.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid invitation link.")
        
    team_id = jwt_payload.get("team_id")
    team_name = jwt_payload.get("team_name")
    
    if not team_id or not team_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed invitation token.")
        
    # Check if user is already in the team
    user_teams = user.get("teams", [])
    if any(t["_id"] == team_id for t in user_teams):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are already a member of this team.")
        
    # Add team to user profile
    joined_team = {
        "_id": team_id,
        "name": team_name,
        "roles": ["Member"]
    }
    await auth_service.repository.add_team(user_id, joined_team)
    
    return {"message": f"Successfully joined team {team_name}!", "team": joined_team}

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
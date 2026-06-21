import uuid
import bcrypt
import jwt
import asyncio
from datetime import datetime, timezone, timedelta
from fastapi import status, HTTPException
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.repositories.auth_repository import AuthRepository
from app.repositories.cache_repository import cache_repository
from app.schemas.auth_schema import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from app.schemas.user_schema import UserSchema

class AuthService:
    def __init__(self):
        self.repository = AuthRepository()
        self.cache_repository = cache_repository

    def _hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def _verify_password(self, password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def _create_tokens(self, user_id: str, roles: list[str]) -> tuple[str, str, str]:
        """Generates an access token, a refresh token, and extracts the access JTI."""
        access_jti = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        # 1. Access Token (Short-lived)
        payload = {
            "sub": user_id,
            "jti": access_jti,
            "roles": roles,
            "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": now
        }
        access_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        # 2. Refresh Token (Long-lived)
        refresh_payload = {
            "sub": user_id,
            "jti": str(uuid.uuid4()),
            "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": now
        }
        refresh_token = jwt.encode(refresh_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        
        return access_token, refresh_token, access_jti
    
    async def register(self, data: RegisterRequest) -> tuple[RegisterResponse, str]:
        email_clean = data.email.lower().strip()
        hashed_password = await asyncio.to_thread(self._hash_password, data.password)
        user_id = str(uuid.uuid4())
        
        user = UserSchema(
            _id=user_id,
            name=data.name.strip(),
            email=email_clean,
            password_hash=hashed_password,
            roles=["user"],
            last_login_at=datetime.now(timezone.utc)
        )
        try:
            await self.repository.create(user.model_dump(by_alias=True))
        except DuplicateKeyError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists"
            )

        # FIX 1: Correct unpack to match the 3 returned values
        access_token, refresh_token, _ = self._create_tokens(user_id, ["user"])
        await self.repository.save_refresh_token(user_id, refresh_token)
        
        return RegisterResponse(user_id=user.id, token=access_token), refresh_token

    async def login(self, data: LoginRequest) -> tuple[LoginResponse, str]:
        email_clean = data.email.lower().strip()
        
        user = await self.repository.find_by_email(email_clean)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        if user.get("locked_until"):
            locked_until = user["locked_until"].replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) < locked_until:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked due to too many failed attempts.",
                )

        password_valid = await asyncio.to_thread(self._verify_password, data.password, user["password_hash"])
        
        if not password_valid:
            updated_user = await self.repository.increment_login_attempt(email_clean)
            attempts = updated_user.get("failed_login_attempts", 0)
            
            if attempts >= settings.MAX_LOGIN_ATTEMPTS:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account locked due to too many failed attempts.",
                )
                
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,   
                detail="Invalid email or password",
            )
        
        await self.repository.reset_login_attempts(email_clean)

        user_roles = user.get("roles", ["user"])
        user_id = str(user["_id"])
        
        # FIX 2: Correct unpack here too!
        access_token, refresh_token, _ = self._create_tokens(user_id, user_roles)
        await self.repository.save_refresh_token(user_id, refresh_token)
        
        return LoginResponse(user_id=user_id, token=access_token), refresh_token

    async def logout(self, token: str):
        try:
            payload = jwt.decode(
                token, 
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_exp": False}
            )
            user_id = payload.get("sub")
            token_id = payload.get("jti")
            exp_timestamp = payload.get("exp")

            if not token_id or not exp_timestamp or not user_id:
                raise HTTPException(status_code=400, detail="Invalid token structure")

            await self.repository.deactivate_user_session(user_id)
            await self.repository.revoke_refresh_token(user_id)

            now = int(datetime.now(timezone.utc).timestamp())
            remaining_seconds = exp_timestamp - now

            if remaining_seconds > 0:
                await self.cache_repository.blacklist_token(token_id, remaining_seconds)

        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        return {"message": "Successfully logged out"}

    async def refresh_session(self, refresh_token: str) -> tuple[str, str]:
        try:
            payload = jwt.decode(refresh_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            user_id = payload.get("sub")
            
            user = await self.repository.find_by_id(user_id)
            if not user or user.get("refresh_token") != refresh_token:
                raise HTTPException(status_code=401, detail="Refresh token is invalid or has been revoked.")
                
            if user.get("locked_until") and user["locked_until"].replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
                raise HTTPException(status_code=423, detail="Account is currently locked.")

            # FIX 3: Pointed uniformly to self._create_tokens
            access_token, new_refresh_token, _ = self._create_tokens(user_id, user.get("roles", ["user"]))
            await self.repository.save_refresh_token(user_id, new_refresh_token)
            
            return access_token, new_refresh_token
            
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Expired or malformed refresh credentials.")
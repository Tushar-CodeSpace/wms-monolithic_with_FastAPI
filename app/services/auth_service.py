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

    def _create_token(self, user_id: str) -> tuple[str, str]:
        token_id = str(uuid.uuid4())
        payload = {
            "sub": user_id,
            "jti": token_id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.now(timezone.utc)
        }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return token, token_id
    
    async def register(self, data: RegisterRequest) -> RegisterResponse:
        email_clean = data.email.lower().strip()
        hashed_password = await asyncio.to_thread(self._hash_password, data.password)
        user_id = str(uuid.uuid4())
        
        user = UserSchema(
            _id=user_id,
            name=data.name.strip(),
            email=email_clean,
            password_hash=hashed_password,
            last_login_at=datetime.now(timezone.utc)
        )
        try:
            await self.repository.create(user.model_dump(by_alias=True))
        except DuplicateKeyError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists"
            )

        token, token_id = self._create_token(user_id)
        return RegisterResponse(user_id=user.id, token=token)

    async def login(self, data: LoginRequest) -> LoginResponse:
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
        
        token, token_id = self._create_token(user["_id"])
        return LoginResponse(user_id=user["_id"], token=token)

    async def logout(self, token: str):
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM], options={"verify_exp": False})
            token_id = payload.get("jti")
            exp_timestamp = payload.get("exp")

            if not token_id or not exp_timestamp:
                raise HTTPException(status_code=400, detail="Invalid token structure")

            now = int(datetime.now(timezone.utc).timestamp())
            remaining_seconds = exp_timestamp - now

            if remaining_seconds > 0:
                await self.cache_repository.blacklist_token(token_id, remaining_seconds)

        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        return {"message": "Successfully logged out"}
import jwt
from fastapi import Request, HTTPException, status
from app.config import settings
from app.repositories.cache_repository import cache_repository

async def get_current_user(request: Request) -> dict:
    """
    Guards routes by inspecting incoming cookies, verifying cryptographic 
    signatures, and matching claims against the in-memory blacklist.
    """
    token_cookie = request.cookies.get("access_token")
    if not token_cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Authentication credentials missing."
        )
        
    token = token_cookie.replace("Bearer ", "") if token_cookie.startswith("Bearer ") else token_cookie
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        token_id = payload.get("jti")
        
        if not token_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed security token.")
            
        # READ from cache_repository to protect endpoints!
        if await cache_repository.is_token_blacklisted(token_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Token has been invalidated via logout. Please log in again."
            )
            
        return payload 
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization token.")
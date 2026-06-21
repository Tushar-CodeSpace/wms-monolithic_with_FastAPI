from app.config import settings
from app.database import users_collection
from datetime import datetime, timezone, timedelta

class AuthRepository:
    async def find_by_email(self, email: str):
        return await users_collection.find_one({"email": email})

    async def find_by_id(self, user_id: str):
        return await users_collection.find_one({"_id": user_id})

    async def create(self, data: dict):
        return await users_collection.insert_one(data)

    async def increment_login_attempt(self, email: str) -> dict:
        """
        Atomically increments failed attempts. If threshold is met,
        calculates and assigns the dynamic lockout timestamp.
        """
        now = datetime.now(timezone.utc)
        lockout_duration = timedelta(minutes=settings.LOCKOUT_MINUTES)
        
        # We pass an aggregation pipeline inside an update call to dynamically evaluate fields
        updated_user = await users_collection.find_one_and_update(
            {"email": email},
            [
                {
                    "$set": {
                        "failed_login_attempts": {
                            "$add": [{"$ifNull": ["$failed_login_attempts", 0]}, 1]
                        },
                        "last_failed_attempt": now
                    }
                },
                {
                    "$set": {
                        "locked_until": {
                            "$cond": {
                                "if": {"$gte": ["$failed_login_attempts", settings.MAX_LOGIN_ATTEMPTS]},
                                "then": now + lockout_duration,
                                "else": None
                            }
                        }
                    }
                }
            ],
            return_document=True # Crucial: Returns the user state AFTER modifications
        )
        return updated_user

    async def reset_login_attempts(self, email: str):
        await users_collection.update_one(
            {"email": email},
            {
                "$set":{
                    "failed_login_attempts": 0,
                    "last_failed_attempt": None,
                    "locked_until": None,
                    "is_active": True,
                    "last_login_at": datetime.now(timezone.utc)
                }
            }
        )

    async def deactivate_user_session(self, user_id: str):
        # sets the user's is_active flag to False
        await users_collection.update_one(
            {"_id": user_id},
            {"$set":{
                    "is_active": False
                }
            }
        )

    async def save_refresh_token(self, user_id: str, refresh_token: str):
        # Save a valid refresh token string to the user profile.
        await users_collection.update_one(
            {"_id": user_id},
            {"$set": {
                "refresh_token": refresh_token
            }}
        )

    async def revoke_refresh_token(self, user_id: str):
        # Remove the refresh token upon logout or breach suspicion.
        await users_collection.update_one(
            {"_id": user_id},
            {"$set": {
                "refresh_token": None
            }}
        )


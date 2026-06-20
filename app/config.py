from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_URI: str
    USER_DATABASE_NAME: str
    BCRYPT_ROUNDS: int = 8
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_MINUTES: int = 60
    
    class Config:
        env_file = ".env"

settings = Settings()
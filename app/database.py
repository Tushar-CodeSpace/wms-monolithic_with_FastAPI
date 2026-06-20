# from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

# client = MongoClient(settings.MONGO_URI)
client = AsyncIOMotorClient(settings.MONGO_URI)

user_db = client[settings.USER_DATABASE_NAME]

users_collection = user_db["users"]
# users_collection.create_index("email", unique=True)
async def init_db():
    print("Initializing MongoDB Indexes...")
    await users_collection.create_index("email", unique=True)
    print("Database initialization complete.")
# from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

# client = MongoClient(settings.MONGO_URI)
client = AsyncIOMotorClient(settings.MONGO_URI)

user_db = client[settings.USER_DATABASE_NAME]

users_collection = user_db["users"]
messages_collection = user_db["messages"]

async def init_db():
    print("Initializing MongoDB Indexes...")
    await users_collection.create_index("email", unique=True)
    await messages_collection.create_index([
        ("sender_id", 1),
        ("receiver_id", 1),
        ("timestamp", 1)
    ])
    print("Database initialization complete.")
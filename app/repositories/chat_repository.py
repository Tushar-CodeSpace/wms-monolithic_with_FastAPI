from app.database import users_collection, messages_collection

class ChatRepository:
    async def save_message(self, message: dict):
        await messages_collection.insert_one(message)

    async def get_chat_history(self, user_a: str, user_b: str, limit: int = 100):
        cursor = messages_collection.find({
            "$or": [
                {"sender_id": user_a, "receiver_id": user_b},
                {"sender_id": user_b, "receiver_id": user_a}
            ]
        }).sort("timestamp", 1).limit(limit)
        return await cursor.to_list(length=limit)

    async def get_all_users(self, exclude_user_id: str):
        cursor = users_collection.find(
            {"_id": {"$ne": exclude_user_id}},
            {"name": 1, "email": 1, "is_active": 1, "roles": 1}
        )
        return await cursor.to_list(length=200)

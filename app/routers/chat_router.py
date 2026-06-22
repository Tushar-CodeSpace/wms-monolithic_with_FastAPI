from fastapi import APIRouter, Depends, status, WebSocket, WebSocketDisconnect
from datetime import datetime, timezone
import jwt
import uuid

from app.config import settings
from app.dependencies.auth_deps import get_current_user
from app.repositories.chat_repository import ChatRepository

router = APIRouter()
chat_repository = ChatRepository()

# ─── CONNECTION MANAGER FOR WEB-SOCKETS ───

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: dict, user_id: str):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_json(message)

    def is_user_online(self, user_id: str) -> bool:
        return user_id in self.active_connections

manager = ConnectionManager()

# ─── CHAT ROUTE DEFINITIONS ───

@router.get("/users")
async def get_chat_users(
    current_user: dict = Depends(get_current_user)
):
    user_id = current_user.get("sub")
    db_users = await chat_repository.get_all_users(exclude_user_id=user_id)
    
    users_list = []
    for u in db_users:
        users_list.append({
            "id": str(u["_id"]),
            "name": u.get("name", ""),
            "email": u.get("email", ""),
            "is_online": manager.is_user_online(str(u["_id"]))
        })
    return users_list

@router.get("/messages/{target_user_id}")
async def get_chat_messages(
    target_user_id: str,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    user_id = current_user.get("sub")
    messages = await chat_repository.get_chat_history(user_id, target_user_id, limit)
    
    formatted = []
    for m in messages:
        formatted.append({
            "id": str(m["_id"]),
            "sender_id": m.get("sender_id"),
            "receiver_id": m.get("receiver_id"),
            "content": m.get("content"),
            "timestamp": m.get("timestamp").isoformat() if isinstance(m.get("timestamp"), datetime) else m.get("timestamp")
        })
    return formatted

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
        
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id = payload.get("sub")
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
        
    await manager.connect(user_id, websocket)
    
    try:
        while True:
            data = await websocket.receive_json()
            receiver_id = data.get("receiver_id")
            content = data.get("content")
            
            if not receiver_id or not content or not content.strip():
                continue
                
            msg_id = f"msg-{str(uuid.uuid4())}"
            now = datetime.now(timezone.utc)
            
            message_record = {
                "_id": msg_id,
                "sender_id": user_id,
                "receiver_id": receiver_id,
                "content": content.strip(),
                "timestamp": now
            }
            
            await chat_repository.save_message(message_record)
            
            msg_payload = {
                "id": msg_id,
                "sender_id": user_id,
                "receiver_id": receiver_id,
                "content": content.strip(),
                "timestamp": now.isoformat()
            }
            
            await manager.send_personal_message(msg_payload, receiver_id)
            await websocket.send_json(msg_payload)
            
    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception:
        manager.disconnect(user_id)

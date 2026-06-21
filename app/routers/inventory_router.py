from fastapi import APIRouter, Depends
from app.dependencies.role_deps import RoleChecker
from app.dependencies.auth_deps import get_current_user

router = APIRouter()

# Allow any authenticated user to view items
@router.get("/items")
async def view_items(current_user: dict = Depends(get_current_user)):
    return {
        "message" : "Here is the inventory list"
    }

# Only allow users with 'admin' or 'manager' roles to create items
@router.post("/items")
async def create_items(admin_user: dict = Depends(RoleChecker(["admin", "manager"]))):
    return {
        "message" : "Item created successfully by authorized personnel."
    }
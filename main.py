from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.database import init_db
from app.routers.auth_router import router as AuthRouter
from app.routers.inventory_router import router as InventoryRouter

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ─── STARTUP ───
    # The event loop is now fully operational, meaning we can await safely!
    await init_db()
    
    yield # The application runs and processes public requests here
    
    # ─── SHUTDOWN ───
    # Put cleanup code here if needed (e.g., closing database connections)
    pass

app = FastAPI(title="WMS prototype", lifespan=lifespan)

app.include_router(
    AuthRouter,
    prefix="/auth",
    tags=["Authentication"],
)

app.include_router(
    InventoryRouter,
    prefix="/inventory",
    tags=["Inventory"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app="main:app",
        reload=True
    )
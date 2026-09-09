"""API routes package"""
from fastapi import APIRouter
from . import upload, jobs, health, websocket

# Create main API router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(upload.router)
api_router.include_router(jobs.router)
api_router.include_router(health.router)
api_router.include_router(websocket.router)

__all__ = ["api_router"]

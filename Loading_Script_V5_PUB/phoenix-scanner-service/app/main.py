"""Main FastAPI application"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.core.config import settings
from app.models.database import init_db
from app.api import api_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("🚀 Starting Phoenix Scanner Service API")
    logger.info(f"   Version: {settings.API_VERSION}")
    logger.info(f"   Host: {settings.API_HOST}:{settings.API_PORT}")
    logger.info(f"   Redis: {settings.REDIS_HOST}:{settings.REDIS_PORT}")
    logger.info(f"   Auth: {'enabled' if settings.ENABLE_AUTH else 'disabled'}")
    
    # Initialize database
    init_db()
    logger.info("✅ Database initialized")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down Phoenix Scanner Service API")


# Create FastAPI application
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description=settings.API_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add GZip compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include API routes
app.include_router(api_router)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "details": str(exc) if settings.DEBUG_MODE else None
        }
    )


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "description": settings.API_DESCRIPTION,
        "docs": "/docs",
        "health": "/api/v1/health",
        "endpoints": {
            "upload": "POST /api/v1/upload",
            "list_jobs": "GET /api/v1/jobs",
            "job_status": "GET /api/v1/jobs/{job_id}",
            "websocket": "WS /ws/{job_id}"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG_MODE,
        workers=settings.API_WORKERS if not settings.DEBUG_MODE else 1,
        log_level=settings.LOG_LEVEL.lower()
    )




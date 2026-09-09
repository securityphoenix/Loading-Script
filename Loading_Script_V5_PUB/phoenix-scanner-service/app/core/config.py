"""Configuration management for Phoenix Scanner Service"""
import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # API Settings
    API_TITLE: str = "Phoenix Scanner Service API"
    API_VERSION: str = "1.0.0"
    API_DESCRIPTION: str = "REST API for Phoenix Security Multi-Scanner Import Tool"
    API_HOST: str = Field(default="0.0.0.0", env="API_HOST")
    API_PORT: int = Field(default=8000, env="API_PORT")
    API_WORKERS: int = Field(default=4, env="API_WORKERS")
    
    # Security
    API_KEY: str = Field(default="changeme-insecure-key", env="API_KEY")
    SECRET_KEY: str = Field(default="changeme-secret-key-for-jwt", env="SECRET_KEY")
    ENABLE_AUTH: bool = Field(default=True, env="ENABLE_AUTH")
    
    # Redis Configuration
    REDIS_HOST: str = Field(default="redis", env="REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, env="REDIS_PORT")
    REDIS_DB: int = Field(default=0, env="REDIS_DB")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    
    @property
    def REDIS_URL(self) -> str:
        """Construct Redis URL"""
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
    
    @property
    def CELERY_BROKER_URL(self) -> str:
        """Celery broker URL (Redis)"""
        return self.REDIS_URL
    
    @property
    def CELERY_RESULT_BACKEND(self) -> str:
        """Celery result backend URL"""
        return self.REDIS_URL
    
    # Database (SQLite for job tracking)
    DATABASE_URL: str = Field(default="sqlite:///./jobs.db", env="DATABASE_URL")
    
    # File Upload Settings
    MAX_UPLOAD_SIZE_MB: int = Field(default=500, env="MAX_UPLOAD_SIZE_MB")
    UPLOAD_DIR: str = Field(default="./uploads", env="UPLOAD_DIR")
    LOG_DIR: str = Field(default="./logs", env="LOG_DIR")
    ALLOWED_EXTENSIONS: list = [".json", ".csv", ".xml", ".zip", ".gz"]
    
    # Worker Settings
    MAX_CONCURRENT_JOBS: int = Field(default=5, env="MAX_CONCURRENT_JOBS")
    JOB_TIMEOUT: int = Field(default=3600, env="JOB_TIMEOUT")  # 1 hour
    CLEANUP_AFTER_DAYS: int = Field(default=7, env="CLEANUP_AFTER_DAYS")
    
    # Phoenix API Credentials (optional defaults, typically overridden per request or via env)
    PHOENIX_CLIENT_ID: Optional[str] = Field(default=None, env="PHOENIX_CLIENT_ID")
    PHOENIX_CLIENT_SECRET: Optional[str] = Field(default=None, env="PHOENIX_CLIENT_SECRET")
    PHOENIX_API_URL: Optional[str] = Field(default=None, env="PHOENIX_API_URL")
    
    # Phoenix Scanner Settings (defaults, can be overridden per request)
    PHOENIX_CONFIG_FILE: str = Field(default="/parent/config_multi_scanner.ini", env="PHOENIX_CONFIG_FILE")
    ENABLE_BATCHING: bool = Field(default=True, env="ENABLE_BATCHING")
    FIX_DATA: bool = Field(default=True, env="FIX_DATA")
    MAX_BATCH_SIZE: int = Field(default=500, env="MAX_BATCH_SIZE")
    MAX_PAYLOAD_MB: float = Field(default=25.0, env="MAX_PAYLOAD_MB")
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    DEBUG_MODE: bool = Field(default=False, env="DEBUG_MODE")
    
    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = Field(default=30, env="WS_HEARTBEAT_INTERVAL")
    WS_MESSAGE_QUEUE_SIZE: int = Field(default=1000, env="WS_MESSAGE_QUEUE_SIZE")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()


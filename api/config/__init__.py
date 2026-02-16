"""
Configuration package for Hunter API.
"""
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings and configuration."""

    app_name: str = "Bro Hunter - Network Threat Hunting Platform"
    app_version: str = "0.2.0"
    api_prefix: str = "/api/v1"
    api_key: str | None = None
    log_root: str | None = None
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    max_file_size: int = 100 * 1024 * 1024
    chunk_size: int = 8192
    high_threat_threshold: float = 0.75
    medium_threat_threshold: float = 0.50
    low_threat_threshold: float = 0.25
    suspicious_port_threshold: int = 1024
    failed_connection_threshold: int = 10
    dns_query_threshold: int = 100

    class Config:
        env_prefix = "BROHUNTER_"
        case_sensitive = False


settings = Settings()

from api.config.allowlists import BeaconAllowlist

__all__ = ["BeaconAllowlist", "Settings", "settings"]

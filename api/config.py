"""
Configuration management for Hunter API.
Handles environment-based settings and application configuration.
"""
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings and configuration."""

    # API Configuration
    app_name: str = "Hunter - Network Threat Hunting Platform"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"

    # CORS Configuration
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # File Processing
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    chunk_size: int = 8192  # For streaming large files

    # Threat Scoring Thresholds
    high_threat_threshold: float = 0.75
    medium_threat_threshold: float = 0.50
    low_threat_threshold: float = 0.25

    # Analysis Configuration
    suspicious_port_threshold: int = 1024  # Ports below this are well-known
    failed_connection_threshold: int = 10  # Failed connections before flagging
    dns_query_threshold: int = 100  # Excessive DNS queries per host

    class Config:
        env_prefix = "HUNTER_"
        case_sensitive = False


# Global settings instance
settings = Settings()

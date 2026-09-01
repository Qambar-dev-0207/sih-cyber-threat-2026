"""
SIH26145 - API Configuration & Environment Settings
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import List
from pydantic import BaseModel, Field

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class ApiConfig(BaseSettings):
        model_config = SettingsConfigDict(
            env_prefix="SIH_",
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
        )

        # Server Bindings
        host: str = Field(default="0.0.0.0", description="Bind host address")
        port: int = Field(default=8000, description="Bind port")
        app_name: str = Field(
            default="SIH26145 Autonomous Passive SOC Streaming Backend",
            description="Application display name",
        )
        version: str = Field(default="1.0.0", description="API Version")
        api_prefix: str = Field(default="/api", description="REST API prefix")

        # CORS Settings
        cors_origins: List[str] = Field(
            default=["*"],
            description="Allowed CORS origins",
        )
        cors_methods: List[str] = Field(
            default=["*"],
            description="Allowed HTTP methods",
        )
        cors_headers: List[str] = Field(
            default=["*"],
            description="Allowed HTTP headers",
        )

        # Telemetry & Broadcaster Timing
        telemetry_interval_sec: float = Field(
            default=0.5,
            description="Broadcaster ticker interval in seconds (500ms)",
        )
        incident_buffer_size: int = Field(
            default=500,
            description="Maximum in-memory incident ring buffer size",
        )

        # Database Fallback Settings
        postgres_host: str = Field(default="localhost", description="PostgreSQL / TimescaleDB host")
        postgres_port: int = Field(default=5432, description="PostgreSQL / TimescaleDB port")
        postgres_db: str = Field(default="sih26145", description="Database name")
        postgres_user: str = Field(default="postgres", description="Database user")
        postgres_password: str = Field(default="postgrespassword", description="Database password")
        enable_timescale: bool = Field(default=False, description="Enable TimescaleDB persistence if available")

        # Hardware Data Diode & Enclave Safety
        hardware_data_diode_enforced: bool = Field(
            default=True,
            description="Enforce hardware data diode isolation (zero return path)",
        )
        requires_human_approval: bool = Field(
            default=True,
            description="Strictly require human approval for all countermeasure executions",
        )

except ImportError:
    # Fallback to BaseModel with manual env reading if pydantic_settings is missing
    class ApiConfig(BaseModel):  # type: ignore
        host: str = Field(default_factory=lambda: os.getenv("SIH_HOST", "0.0.0.0"))
        port: int = Field(default_factory=lambda: int(os.getenv("SIH_PORT", "8000")))
        app_name: str = Field(default="SIH26145 Autonomous Passive SOC Streaming Backend")
        version: str = Field(default="1.0.0")
        api_prefix: str = Field(default="/api")
        cors_origins: List[str] = Field(default_factory=lambda: ["*"])
        cors_methods: List[str] = Field(default_factory=lambda: ["*"])
        cors_headers: List[str] = Field(default_factory=lambda: ["*"])
        telemetry_interval_sec: float = Field(
            default_factory=lambda: float(os.getenv("SIH_TELEMETRY_INTERVAL_SEC", "0.5"))
        )
        incident_buffer_size: int = Field(
            default_factory=lambda: int(os.getenv("SIH_INCIDENT_BUFFER_SIZE", "500"))
        )
        postgres_host: str = Field(default_factory=lambda: os.getenv("POSTGRES_HOST", "localhost"))
        postgres_port: int = Field(default_factory=lambda: int(os.getenv("POSTGRES_PORT", "5432")))
        postgres_db: str = Field(default_factory=lambda: os.getenv("POSTGRES_DB", "sih26145"))
        postgres_user: str = Field(default_factory=lambda: os.getenv("POSTGRES_USER", "postgres"))
        postgres_password: str = Field(default_factory=lambda: os.getenv("POSTGRES_PASSWORD", "postgrespassword"))
        enable_timescale: bool = Field(
            default_factory=lambda: os.getenv("SIH_ENABLE_TIMESCALE", "false").lower() in ("1", "true", "yes")
        )
        hardware_data_diode_enforced: bool = True
        requires_human_approval: bool = True


@lru_cache()
def get_config() -> ApiConfig:
    """Returns a cached ApiConfig singleton instance."""
    return ApiConfig()

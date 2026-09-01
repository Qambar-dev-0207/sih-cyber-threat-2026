"""
SIH26145 - FastAPI Real-Time Streaming Backend Application
Initializes the FastAPI application with lifespan management, CORS middleware,
custom exception handlers, REST and WebSocket route registrations.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.config import ApiConfig, get_config
from src.api.routes import (
    health_router,
    incidents_router,
    metrics_router,
    simulate_router,
    websockets_router,
)
from src.api.services.telemetry_service import (
    start_telemetry_broadcaster,
    stop_telemetry_broadcaster,
)
from src.api.state import AppState, get_app_state

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sih.api.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan manager controlling background tasks,
    database connection pools, and real-time telemetry streaming ticker.
    """
    logger.info("Initializing SIH26145 Autonomous Passive SOC Streaming Backend...")
    state: AppState = get_app_state()

    # Launch background line-rate telemetry broadcaster
    start_telemetry_broadcaster(state)
    logger.info(
        f"Real-time telemetry ticker started (Interval: {state.config.telemetry_interval_sec}s). "
        f"Data Diode Enclave Mode: Hardware Enforced (Human Approval Required)."
    )

    yield

    # Clean shutdown
    logger.info("Shutting down SIH26145 backend...")
    await stop_telemetry_broadcaster(state)
    state.db.close()
    logger.info("All background tasks and database pools closed successfully.")


def create_app(config: Optional[ApiConfig] = None) -> FastAPI:
    """
    FastAPI application factory.
    """
    cfg = config or get_config()

    app = FastAPI(
        title=cfg.app_name,
        version=cfg.version,
        description=(
            "Autonomous Passive Network Monitoring SOC Defense Backend. "
            "Streams line-rate telemetry and agentic incident triage to Cyberpunk SOC Analyst Dashboards "
            "with physical data diode air-gap enforcement."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Attach CORS Middleware (Allow all origins/methods/headers for local SOC dashboard)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=cfg.cors_methods,
        allow_headers=cfg.cors_headers,
    )

    # Register Custom Exception Handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "status_code": exc.status_code,
                "path": str(request.url.path),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation Error",
                "details": exc.errors(),
                "status_code": 422,
                "path": str(request.url.path),
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "message": str(exc),
                "status_code": 500,
                "path": str(request.url.path),
            },
        )

    # Root status endpoint
    @app.get("/", tags=["Root"])
    async def root() -> Dict[str, Any]:
        return {
            "name": cfg.app_name,
            "version": cfg.version,
            "status": "operational",
            "enclave": "AIR_GAPPED_PASSIVE_DATA_DIODE",
            "human_approval_enforced": cfg.requires_human_approval,
            "endpoints": {
                "health": f"{cfg.api_prefix}/health",
                "metrics": f"{cfg.api_prefix}/metrics",
                "incidents": f"{cfg.api_prefix}/incidents",
                "simulate": f"{cfg.api_prefix}/simulate/{{scenario}}",
                "ws_telemetry": "/ws/telemetry",
                "ws_incidents": "/ws/incidents",
                "docs": "/docs",
            },
        }

    # Register REST Routers under prefix (/api)
    app.include_router(health_router, prefix=cfg.api_prefix)
    app.include_router(metrics_router, prefix=cfg.api_prefix)
    app.include_router(incidents_router, prefix=cfg.api_prefix)
    app.include_router(simulate_router, prefix=cfg.api_prefix)

    # Register WebSocket Routers (root paths /ws/*)
    app.include_router(websockets_router)

    return app


# Application singleton
app = create_app()

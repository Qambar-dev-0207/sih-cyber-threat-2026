"""
SIH26145 - API Route Handlers Package
"""

from src.api.routes.health import router as health_router
from src.api.routes.incidents import router as incidents_router
from src.api.routes.metrics import router as metrics_router
from src.api.routes.simulate import router as simulate_router
from src.api.routes.websockets import router as websockets_router

__all__ = [
    "health_router",
    "metrics_router",
    "incidents_router",
    "simulate_router",
    "websockets_router",
]

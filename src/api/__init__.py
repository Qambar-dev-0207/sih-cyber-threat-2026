"""
SIH26145 - Real-Time Streaming Backend API Package
Provides REST and WebSocket endpoints for Cyberpunk SOC Analyst Defense Dashboard,
live line-rate telemetry broadcasting, incident triage inspection, and synthetic scenario replaying.
"""

from src.api.app import app, create_app

__all__ = ["app", "create_app"]

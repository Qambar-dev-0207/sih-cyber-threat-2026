"""
SIH26145 - WebSocket Streaming Endpoints
Provides real-time continuous feeds for Line-Rate Telemetry Gauges (/ws/telemetry)
and Live Threat & Incident Matrices (/ws/incidents).
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from src.api.services.telemetry_service import generate_instantaneous_telemetry
from src.api.state import AppState, get_app_state

logger = logging.getLogger("sih.api.websockets")
router = APIRouter(tags=["WebSocket Real-Time Streams"])


@router.websocket("/ws/telemetry")
async def websocket_telemetry_stream(
    websocket: WebSocket,
    app_state: AppState = Depends(get_app_state),
) -> None:
    """
    WebSocket endpoint broadcasting real-time line-rate telemetry every 500ms.
    Receives incoming client keep-alives / ping frames.
    """
    await app_state.connection_manager.connect_telemetry(websocket)

    # Immediately emit initial telemetry frame upon connection
    try:
        initial_msg = generate_instantaneous_telemetry(app_state)
        await websocket.send_json(initial_msg.model_dump())
    except Exception as exc:
        logger.debug(f"Failed to send initial telemetry frame: {exc}")
        await app_state.connection_manager.disconnect_telemetry(websocket)
        return

    try:
        while True:
            # Maintain active connection listening for client pings or control messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info("Telemetry WebSocket client disconnected normally.")
    except Exception as exc:
        logger.debug(f"Telemetry WebSocket connection error: {exc}")
    finally:
        await app_state.connection_manager.disconnect_telemetry(websocket)


@router.websocket("/ws/incidents")
async def websocket_incidents_stream(
    websocket: WebSocket,
    app_state: AppState = Depends(get_app_state),
) -> None:
    """
    WebSocket push endpoint broadcasting newly triaged incidents in real time.
    Also provides recent incident snapshot on initial connect.
    """
    await app_state.connection_manager.connect_incidents(websocket)

    # Send connection acknowledgment
    try:
        await websocket.send_json({
            "event_type": "CONNECTED",
            "message": "Connected to SIH26145 Real-Time Threat Feed stream.",
            "buffer_count": app_state.incident_buffer.count(),
        })
    except Exception as exc:
        logger.debug(f"Failed to send incident stream connection ack: {exc}")
        await app_state.connection_manager.disconnect_incidents(websocket)
        return

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info("Incident feed WebSocket client disconnected normally.")
    except Exception as exc:
        logger.debug(f"Incident feed WebSocket connection error: {exc}")
    finally:
        await app_state.connection_manager.disconnect_incidents(websocket)

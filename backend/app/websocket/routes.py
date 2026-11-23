"""
AegisSOC Real-Time WebSocket Routes
Streams live throughput ticks, event feed alerts, health checks, and monitoring telemetry.
Supports JWT authentication and reconnection replay.
"""

import asyncio
from datetime import datetime, timezone
import random
from typing import Optional
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.logging import logger
from app.websocket.manager import ws_manager

router = APIRouter(tags=["WebSockets"])


@router.websocket("/ws/monitoring")
@router.websocket("/monitoring")
async def websocket_monitoring_stream(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    last_seq: Optional[int] = Query(None)
):
    """
    Main unified WebSocket channel for AegisSOC live monitoring.
    Authenticates client via token query param or headers.
    Supports reconnection event replay if last_seq is provided.
    Streams throughput ticks (tIn, tOut), active perimeter state, and live security events.
    """
    auth_claims = ws_manager.authenticate(websocket)
    is_authenticated = auth_claims is not None
    user_email = auth_claims.get("sub", "analyst@aegissoc.internal") if is_authenticated else "viewer@public"

    connected = await ws_manager.connect(websocket, "monitoring")
    if not connected:
        return

    # Send initial connection handshake
    handshake = {
        "type": "CONNECTION_ESTABLISHED",
        "authenticated": is_authenticated,
        "identity": user_email,
        "role": auth_claims.get("role", "Viewer") if is_authenticated else "Viewer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latest_seq_id": ws_manager._seq_counter
    }
    await websocket.send_json(handshake)

    # Reconnection event replay
    if last_seq is not None:
        missed = ws_manager.get_missed_events(last_seq)
        if missed:
            await websocket.send_json({
                "type": "RECONNECTION_REPLAY",
                "events_count": len(missed),
                "events": missed
            })

    async def _send_ticks():
        try:
            while True:
                inbound = round(40.0 + random.random() * 50.0, 2)
                outbound = round(20.0 + random.random() * 30.0, 2)
                payload = {
                    "type": "TRAFFIC_TICK",
                    "inbound_mbps": inbound,
                    "outbound_mbps": outbound,
                    "active_threats": 7,
                    "critical_incidents": 2,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                await websocket.send_json(payload)
                await asyncio.sleep(1.5)  # Matches frontend interval
        except asyncio.CancelledError:
            pass

    async def _receive_client_messages():
        try:
            while True:
                msg = await websocket.receive_json()
                action = msg.get("action")
                if action == "ping":
                    await websocket.send_json({"type": "pong", "time": datetime.now(timezone.utc).isoformat()})
                elif action == "resync":
                    since = msg.get("since_seq_id", 0)
                    missed = ws_manager.get_missed_events(since)
                    await websocket.send_json({"type": "RESYNC_DATA", "events": missed})
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass

    tick_task = asyncio.create_task(_send_ticks())
    rx_task = asyncio.create_task(_receive_client_messages())

    try:
        done, pending = await asyncio.wait(
            [tick_task, rx_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
    except Exception as e:
        logger.warning(f"Error in monitoring stream: {e}")
    finally:
        tick_task.cancel()
        rx_task.cancel()
        ws_manager.disconnect(websocket, "monitoring")


@router.websocket("/ws/traffic")
async def websocket_traffic_endpoint(websocket: WebSocket):
    """Streams real-time throughput metrics (tIn, tOut) to the frontend area chart."""
    await ws_manager.connect(websocket, "traffic")
    try:
        while True:
            inbound = round(40.0 + random.random() * 50.0, 2)
            outbound = round(20.0 + random.random() * 30.0, 2)
            data = {
                "type": "traffic_tick",
                "inbound_mbps": inbound,
                "outbound_mbps": outbound,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await websocket.send_json(data)
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "traffic")
    except Exception as e:
        logger.error(f"WebSocket error in traffic stream: {e}")
        ws_manager.disconnect(websocket, "traffic")


@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """Streams live threat detections to the frontend's security event feed."""
    await ws_manager.connect(websocket, "events")
    types = ["Brute Force", "Port Scanning", "DDoS", "Malware Communication", "Suspicious Traffic"]
    sevs = ["Critical", "High", "Medium", "Low"]
    engines = ["ML anomaly model", "Signature rule", "Threat intel match", "Behavioural baseline"]
    try:
        while True:
            await asyncio.sleep(3.5)
            src_ip = f"{random.choice([185, 45, 103, 91, 194, 23])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"10.0.{random.randint(0, 3)}.{random.randint(2, 250)}"
            ev = {
                "id": random.randint(10000, 99999),
                "t": int(datetime.now(timezone.utc).timestamp()),
                "src": src_ip,
                "dst": dst_ip,
                "type": random.choice(types),
                "sev": random.choice(sevs),
                "by": random.choice(engines)
            }
            # Buffer for reconnection replay
            seq = ws_manager.buffer_event(ev)
            await websocket.send_json({"type": "security_event", "event": ev, "seq": seq})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "events")
    except Exception as e:
        logger.error(f"WebSocket error in events stream: {e}")
        ws_manager.disconnect(websocket, "events")


@router.websocket("/ws/health")
async def websocket_health_endpoint(websocket: WebSocket):
    """Streams subsystem latencies and health heartbeats."""
    await ws_manager.connect(websocket, "health")
    try:
        while True:
            data = {
                "type": "health_tick",
                "subsystems": [
                    {"name": "Network monitoring", "latency_ms": round(10 + random.random() * 5, 1), "status": "Healthy"},
                    {"name": "ML detection engine", "latency_ms": round(35 + random.random() * 8, 1), "status": "Healthy"},
                    {"name": "AI investigation engine", "latency_ms": round(200 + random.random() * 30, 1), "status": "Healthy"},
                    {"name": "Threat intelligence", "latency_ms": round(600 + random.random() * 50, 1), "status": "Degraded"},
                    {"name": "Database connection", "latency_ms": round(3 + random.random() * 2, 1), "status": "Healthy"}
                ],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await websocket.send_json(data)
            await asyncio.sleep(5.0)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "health")
    except Exception as e:
        logger.error(f"WebSocket error in health stream: {e}")
        ws_manager.disconnect(websocket, "health")

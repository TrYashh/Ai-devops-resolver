"""
backend/main.py — Backend API Server
REST endpoints + WebSocket for real-time dashboard communication
Bridges frontend ↔ MCP Server ↔ AI Agent
"""

import asyncio
import json
import os
import sys
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx
import uvicorn
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    HTTPException, Depends, Request, BackgroundTasks,
    status as http_status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.shared import (
    load_config, setup_logger, generate_id,
    Severity, ActionType, IncidentStatus,
)

CONFIG = load_config(os.path.join(Path(__file__).parent.parent, "config.yaml"))
logger = setup_logger("backend", CONFIG)

MCP_BASE = f"http://mcp-server:{CONFIG['mcp_server']['port']}"
MCP_KEY    = CONFIG["mcp_server"].get("api_key", "dev-api-key-change-me")
JWT_SECRET = CONFIG["mcp_server"].get("jwt_secret", "dev-secret")
JWT_ALG    = CONFIG["mcp_server"].get("jwt_algorithm", "HS256")

app = FastAPI(
    title="AI DevOps Resolver — Backend API",
    version="1.0.0",
    description="Orchestration API for the AI DevOps Incident Auto-Resolver dashboard",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG["security"]["allowed_origins"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ─── WebSocket Manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)
        logger.info(f"WS connected. Active: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, message: Dict):
        dead = set()
        payload = json.dumps(message, default=str)
        for ws in self.active:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active.discard(ws)

    async def send_personal(self, ws: WebSocket, message: Dict):
        try:
            await ws.send_text(json.dumps(message, default=str))
        except Exception:
            self.active.discard(ws)


manager = ConnectionManager()

# ─── In-Memory Agent State (shared reference) ─────────────────────────────────

_agent_state = {
    "autonomous_mode": True,
    "running": True,
    "incidents": [],
    "actions": [],
    "suggestions": [],
    "action_count_hour": 0,
}

_services = ["api-service", "worker-service", "db-proxy", "cache-service"]
_metrics_cache: Dict[str, Dict] = {}
_incidents: List[Dict] = []
_actions: List[Dict] = []
_logs_cache: List[Dict] = []

# ─── MCP HTTP Client ──────────────────────────────────────────────────────────

MCP_HEADERS = {"X-API-Key": MCP_KEY, "Content-Type": "application/json"}

async def mcp_post(endpoint: str, payload: Dict) -> Dict:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                f"{MCP_BASE}/{endpoint}",
                json=payload,
                headers=MCP_HEADERS,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"MCP error {endpoint}: {e.response.status_code}")
            raise HTTPException(status_code=502, detail=f"MCP error: {e.response.text[:200]}")
        except httpx.RequestError as e:
            logger.error(f"MCP connection error: {e}")
            raise HTTPException(status_code=503, detail="MCP server unavailable")

async def mcp_get(endpoint: str) -> Dict:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{MCP_BASE}/{endpoint}", headers=MCP_HEADERS)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"MCP GET {endpoint} failed: {e}")
            return {}


# ─── Auth ─────────────────────────────────────────────────────────────────────

bearer = HTTPBearer(auto_error=False)

async def optional_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> Optional[str]:
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("sub")
    except JWTError:
        return None


# ─── Request Models ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class ManualActionRequest(BaseModel):
    action_type: str
    service_name: str
    parameters: Dict[str, Any] = {}
    reason: str


class AgentModeRequest(BaseModel):
    autonomous: bool


# ─── Auth Endpoint ────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(body: LoginRequest):
    result = await mcp_post("auth/token", {"username": body.username, "password": body.password})
    return result


# ─── Dashboard Endpoints ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    mcp_ok = False
    try:
        r = await mcp_get("health")
        mcp_ok = r.get("status") == "ok"
    except Exception:
        pass
    return {
        "status": "ok",
        "mcp_server": "ok" if mcp_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }


@app.get("/api/metrics")
async def get_all_metrics():
    """Get live metrics for all services."""
    try:
        data = await mcp_get("state/metrics/all")
        return data
    except Exception:
        # Return simulated data as fallback
        return {
            "metrics": {svc: _simulate_metrics(svc) for svc in _services},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@app.get("/api/metrics/{service_name}")
async def get_service_metrics(service_name: str, include_history: bool = False):
    result = await mcp_post("tools/get_metrics", {
        "service_name": service_name,
        "include_history": include_history,
    })
    return result


@app.get("/api/logs/{service_name}")
async def get_logs(
    service_name: str,
    time_range: str = "1h",
    level_filter: Optional[str] = None,
    search_term: Optional[str] = None,
    limit: int = 100,
):
    result = await mcp_post("tools/get_logs", {
        "service_name": service_name,
        "time_range": time_range,
        "level_filter": level_filter,
        "search_term": search_term,
        "limit": limit,
    })
    return result


@app.get("/api/incidents")
async def get_incidents():
    return {"incidents": _incidents, "total": len(_incidents)}


@app.get("/api/actions")
async def get_actions(limit: int = 50):
    try:
        data = await mcp_get(f"state/action_log?limit={limit}")
        return data
    except Exception:
        return {"actions": _actions[-limit:], "total": len(_actions)}


@app.get("/api/notifications")
async def get_notifications(limit: int = 30):
    return await mcp_get(f"state/notifications?limit={limit}")


@app.get("/api/agent/status")
async def agent_status():
    return {
        **_agent_state,
        "incidents": _incidents[-20:],
        "actions": _actions[-20:],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Control Endpoints ────────────────────────────────────────────────────────

@app.post("/api/agent/mode")
async def set_agent_mode(body: AgentModeRequest):
    _agent_state["autonomous_mode"] = body.autonomous
    mode = "AUTONOMOUS" if body.autonomous else "SUGGESTION"
    logger.info(f"Agent mode set to {mode}")
    # Broadcast mode change to all WS clients
    await manager.broadcast({
        "type": "agent_mode_changed",
        "autonomous": body.autonomous,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return {"success": True, "mode": mode}


@app.post("/api/actions/restart")
async def restart_service(service_name: str, reason: str = "Manual restart from dashboard"):
    result = await mcp_post("tools/restart_service", {
        "service_name": service_name,
        "reason": reason,
        "force": False,
    })
    action_entry = {
        "id": generate_id("MAN"),
        "tool": "restart_service",
        "service": service_name,
        "reason": reason,
        "result": result,
        "autonomous": False,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _actions.append(action_entry)
    await manager.broadcast({"type": "action_executed", "action": action_entry})
    return result


@app.post("/api/actions/scale")
async def scale_service(service_name: str, replicas: int, reason: str = "Manual scale from dashboard"):
    result = await mcp_post("tools/scale_service", {
        "service_name": service_name,
        "replicas": replicas,
        "reason": reason,
    })
    action_entry = {
        "id": generate_id("MAN"),
        "tool": "scale_service",
        "service": service_name,
        "replicas": replicas,
        "reason": reason,
        "result": result,
        "autonomous": False,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _actions.append(action_entry)
    await manager.broadcast({"type": "action_executed", "action": action_entry})
    return result


@app.post("/api/actions/notify")
async def notify_team(message: str, severity: str = "warning", service_name: Optional[str] = None):
    return await mcp_post("tools/notify_team", {
        "message": message,
        "severity": severity,
        "service_name": service_name,
    })


@app.post("/api/actions/manual")
async def manual_action(body: ManualActionRequest):
    """Generic manual action trigger from dashboard."""
    if body.action_type == "restart_service":
        return await restart_service(body.service_name, body.reason)
    elif body.action_type == "scale_service":
        replicas = body.parameters.get("replicas", 2)
        return await scale_service(body.service_name, replicas, body.reason)
    elif body.action_type == "notify_team":
        return await notify_team(body.reason, "warning", body.service_name)
    raise HTTPException(status_code=400, detail=f"Unknown action: {body.action_type}")


# ─── WebSocket Endpoint ───────────────────────────────────────────────────────

@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # Send initial state
    await manager.send_personal(websocket, {
        "type": "initial_state",
        "agent_mode": _agent_state["autonomous_mode"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                msg = json.loads(data)
                await _handle_ws_message(websocket, msg)
            except asyncio.TimeoutError:
                # Send heartbeat
                await manager.send_personal(websocket, {"type": "heartbeat", "ts": time.time()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"WS disconnected. Active: {len(manager.active)}")
    except Exception as e:
        logger.error(f"WS error: {e}")
        manager.disconnect(websocket)


async def _handle_ws_message(ws: WebSocket, msg: Dict):
    msg_type = msg.get("type")
    if msg_type == "subscribe_metrics":
        await manager.send_personal(ws, {"type": "ack", "subscribed": "metrics"})
    elif msg_type == "ping":
        await manager.send_personal(ws, {"type": "pong"})


# ─── Background Broadcaster ───────────────────────────────────────────────────

async def _broadcast_loop():
    """Push live metrics + incidents to all connected dashboard clients."""
    interval = CONFIG["websocket"].get("broadcast_interval", 5)
    while True:
        await asyncio.sleep(interval)
        if not manager.active:
            continue
        try:
            metrics_data = await mcp_get("state/metrics/all")
            await manager.broadcast({
                "type": "metrics_update",
                "data": metrics_data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            # Fallback to simulated metrics
            await manager.broadcast({
                "type": "metrics_update",
                "data": {
                    "metrics": {svc: _simulate_metrics(svc) for svc in _services},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            })


def _simulate_metrics(service: str) -> Dict:
    return {
        "service_name": service,
        "cpu_percent": round(random.uniform(20, 95), 2),
        "memory_percent": round(random.uniform(30, 88), 2),
        "error_rate": round(random.uniform(0, 12), 2),
        "request_rate": round(random.uniform(50, 600), 1),
        "response_time_ms": round(random.uniform(80, 1500), 1),
        "restart_count": random.randint(0, 5),
        "uptime_seconds": random.randint(3600, 604800),
        "status": random.choices(["running", "running", "running", "degraded", "stopped"], weights=[80, 5, 5, 7, 3])[0],
        "replicas": random.randint(1, 6),
        "healthy_replicas": random.randint(1, 4),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Simulate Incident Generator ─────────────────────────────────────────────

async def _incident_simulator():
    """Simulates realistic incidents for demo purposes."""
    await asyncio.sleep(10)
    incident_templates = [
        {"type": "high_cpu",       "severity": "critical", "svc": "api-service",    "msg": "CPU spike to 94% — possible memory leak or traffic surge"},
        {"type": "service_crash",  "severity": "critical", "svc": "worker-service", "msg": "Service crashed — OOMKilled by Kubernetes"},
        {"type": "high_error_rate","severity": "warning",  "svc": "db-proxy",       "msg": "Error rate elevated: 23 errors/min — connection pool exhausted"},
        {"type": "slow_response",  "severity": "warning",  "svc": "api-service",    "msg": "P99 latency degraded to 3.2s"},
        {"type": "crash_loop",     "severity": "critical", "svc": "cache-service",  "msg": "CrashLoopBackOff detected — 4 restarts in 8 minutes"},
    ]
    while True:
        await asyncio.sleep(random.randint(20, 60))
        template = random.choice(incident_templates)
        incident = {
            "id": generate_id("INC"),
            "service_name": template["svc"],
            "title": template["msg"],
            "severity": template["severity"],
            "status": "open",
            "anomaly_type": template["type"],
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        _incidents.append(incident)
        if len(_incidents) > 100:
            _incidents.pop(0)

        await manager.broadcast({"type": "new_incident", "incident": incident})

        # Simulate AI action after a delay
        await asyncio.sleep(random.randint(3, 8))
        if _agent_state["autonomous_mode"]:
            action_map = {
                "high_cpu":        ("scale_service", {"replicas": 4}),
                "service_crash":   ("restart_service", {}),
                "high_error_rate": ("notify_team", {}),
                "slow_response":   ("scale_service", {"replicas": 3}),
                "crash_loop":      ("notify_team", {}),
            }
            action_info = action_map.get(template["type"], ("notify_team", {}))
            action = {
                "id": generate_id("ACT"),
                "incident_id": incident["id"],
                "service_name": template["svc"],
                "action_type": action_info[0],
                "parameters": action_info[1],
                "reasoning": f"AI detected {template['type']} on {template['svc']}",
                "status": "success",
                "autonomous": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            _actions.append(action)
            await manager.broadcast({"type": "action_executed", "action": action})

            # Resolve incident
            await asyncio.sleep(random.randint(5, 15))
            incident["status"] = "resolved"
            incident["resolved_at"] = datetime.now(timezone.utc).isoformat()
            await manager.broadcast({"type": "incident_resolved", "incident": incident})


@app.on_event("startup")
async def startup():
    asyncio.create_task(_broadcast_loop())
    asyncio.create_task(_incident_simulator())
    logger.info("Backend server started")


if __name__ == "__main__":
    srv_cfg = CONFIG["server"]
    uvicorn.run(
        "backend.main:app",
        host=srv_cfg["host"],
        port=srv_cfg["port"],
        log_level="info",
        reload=srv_cfg.get("reload", False),
    )

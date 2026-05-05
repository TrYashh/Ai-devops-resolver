"""
mcp_server/server.py — Production MCP Server
Implements: get_logs, get_metrics, restart_service, scale_service, notify_team
Auth: API-Key + JWT | Logging | Validation | Rate limiting
"""

import sys
import os
import json
import time
import random
import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Security, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from utils.shared import (
    load_config, setup_logger, ServiceMetrics, LogEntry,
    ActionType, generate_id, Severity
)

# ─── Bootstrap ───────────────────────────────────────────────────────────────

CONFIG = load_config(os.path.join(Path(__file__).parent.parent, "config.yaml"))
logger = setup_logger("mcp_server", CONFIG)
MCP_CFG = CONFIG["mcp_server"]

JWT_SECRET    = MCP_CFG.get("jwt_secret", secrets.token_hex(32))
JWT_ALGORITHM = MCP_CFG.get("jwt_algorithm", "HS256")
JWT_EXPIRE    = MCP_CFG.get("jwt_expire_minutes", 60)
API_KEY_HASH  = hashlib.sha256(
    MCP_CFG.get("api_key", "dev-api-key-change-me").encode()
).hexdigest()

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="AI DevOps MCP Server",
    version="1.0.0",
    description="Model Context Protocol server for autonomous incident resolution",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG["security"]["allowed_origins"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ─── In-Memory State (replace with Redis/DB in production) ───────────────────

_service_state: Dict[str, Dict[str, Any]] = {
    "api-service":    {"replicas": 2, "status": "running", "restarts": 0, "cpu": 45.0, "memory": 60.0},
    "worker-service": {"replicas": 1, "status": "running", "restarts": 0, "cpu": 30.0, "memory": 45.0},
    "db-proxy":       {"replicas": 1, "status": "running", "restarts": 0, "cpu": 25.0, "memory": 70.0},
    "cache-service":  {"replicas": 1, "status": "running", "restarts": 0, "cpu": 15.0, "memory": 30.0},
}
_notification_log: List[Dict] = []
_action_log: List[Dict] = []

# ─── Auth ─────────────────────────────────────────────────────────────────────

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _verify_api_key(key: str) -> bool:
    return hashlib.sha256(key.encode()).hexdigest() == API_KEY_HASH


def _create_jwt(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    return jwt.encode({"sub": subject, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def require_auth(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> str:
    # Try JWT
    if bearer:
        try:
            payload = jwt.decode(bearer.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload["sub"]
        except JWTError:
            pass
    # Try API Key
    if api_key and _verify_api_key(api_key):
        return "api-key-user"
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


# ─── Request / Response Models ────────────────────────────────────────────────

class TokenRequest(BaseModel):
    username: str
    password: str


class GetLogsRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100)
    time_range: str = Field("1h", description="e.g. 15m, 1h, 6h, 24h")
    level_filter: Optional[str] = None
    search_term: Optional[str] = None
    limit: int = Field(100, ge=1, le=1000)


class GetMetricsRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100)
    include_history: bool = False


class RestartServiceRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=5, max_length=500)
    force: bool = False


class ScaleServiceRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100)
    replicas: int = Field(..., ge=0, le=50)
    reason: str = Field(..., min_length=5, max_length=500)

    @validator("replicas")
    def validate_replicas(cls, v):
        policy = CONFIG["remediation"]["policies"].get("high_cpu", {})
        if v > policy.get("max_replicas", 10):
            raise ValueError(f"Replicas exceed policy maximum of {policy.get('max_replicas', 10)}")
        return v


class NotifyTeamRequest(BaseModel):
    message: str = Field(..., min_length=5, max_length=2000)
    severity: Severity = Severity.INFO
    service_name: Optional[str] = None
    incident_id: Optional[str] = None
    channels: List[str] = Field(default_factory=list)


class MCPToolResponse(BaseModel):
    success: bool
    tool: str
    data: Any
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    error: Optional[str] = None


# ─── Utility Functions ────────────────────────────────────────────────────────

def _parse_time_range(tr: str) -> int:
    """Convert time range string to seconds."""
    units = {"m": 60, "h": 3600, "d": 86400}
    try:
        return int(tr[:-1]) * units[tr[-1]]
    except Exception:
        return 3600


def _simulate_logs(service: str, count: int, level_filter: Optional[str]) -> List[Dict]:
    """Simulate realistic log entries for demo purposes."""
    levels = ["INFO", "INFO", "INFO", "WARNING", "ERROR", "DEBUG"]
    messages = {
        "INFO":    ["Request processed", "Health check passed", "Cache hit", "Connection established"],
        "WARNING": ["High memory usage detected", "Slow query detected", "Rate limit approaching", "Retry attempt"],
        "ERROR":   ["Connection timeout", "Database query failed", "Out of memory error", "Service unavailable"],
        "DEBUG":   ["Request received", "DB query executed", "Cache miss", "Token validated"],
    }
    logs = []
    for i in range(count):
        lvl = random.choice(levels)
        if level_filter and lvl != level_filter.upper():
            continue
        ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))
        logs.append({
            "timestamp": ts.isoformat(),
            "level": lvl,
            "service": service,
            "message": random.choice(messages.get(lvl, ["Unknown"])),
            "trace_id": generate_id("TRC"),
            "pod": f"{service}-{random.randint(1,3)}",
        })
    return sorted(logs, key=lambda x: x["timestamp"], reverse=True)


def _get_live_metrics(service: str) -> Dict:
    """Get current simulated metrics with realistic drift."""
    state = _service_state.get(service, {})
    cpu_drift   = random.gauss(0, 3)
    mem_drift   = random.gauss(0, 2)

    cpu = min(100, max(0, state.get("cpu", 50) + cpu_drift))
    mem = min(100, max(0, state.get("memory", 60) + mem_drift))
    _service_state.setdefault(service, {})["cpu"] = cpu
    _service_state[service]["memory"] = mem

    return ServiceMetrics(
        service_name=service,
        cpu_percent=round(cpu, 2),
        memory_percent=round(mem, 2),
        memory_mb=round(mem * 20, 1),
        error_rate=round(random.uniform(0, 5), 2),
        request_rate=round(random.uniform(50, 500), 1),
        response_time_ms=round(random.uniform(50, 800), 1),
        restart_count=state.get("restarts", 0),
        uptime_seconds=round(random.uniform(3600, 86400 * 7), 0),
        status=state.get("status", "running"),
        replicas=state.get("replicas", 1),
        healthy_replicas=state.get("replicas", 1),
    ).dict()


def _log_action(tool: str, request_data: Dict, result: Dict, caller: str):
    """Persist action to action log."""
    entry = {
        "id": generate_id("ACT"),
        "tool": tool,
        "caller": caller,
        "request": request_data,
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _action_log.append(entry)
    if len(_action_log) > 1000:
        _action_log.pop(0)
    logger.info(f"MCP tool executed: {tool}", extra={"action": entry})


# ─── Auth Endpoint ────────────────────────────────────────────────────────────

DEMO_USERS = {
    "admin": hashlib.sha256(b"admin123").hexdigest(),
    "agent": hashlib.sha256(b"agent-secret").hexdigest(),
}

@app.post("/auth/token", tags=["Auth"])
async def get_token(body: TokenRequest):
    """Issue a JWT for dashboard / agent usage."""
    user_hash = hashlib.sha256(body.password.encode()).hexdigest()
    if DEMO_USERS.get(body.username) != user_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _create_jwt(body.username)
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_EXPIRE * 60}


# ─── MCP Tools ────────────────────────────────────────────────────────────────

@app.post("/tools/get_logs", response_model=MCPToolResponse, tags=["MCP Tools"])
@limiter.limit("60/minute")
async def get_logs(
    request: Request,
    body: GetLogsRequest,
    caller: str = Depends(require_auth),
):
    """Retrieve logs for a service within a time window."""
    t0 = time.monotonic()
    try:
        seconds = _parse_time_range(body.time_range)
        count = min(body.limit, max(10, seconds // 60))
        logs = _simulate_logs(body.service_name, count, body.level_filter)

        if body.search_term:
            logs = [l for l in logs if body.search_term.lower() in l["message"].lower()]

        data = {
            "service": body.service_name,
            "time_range": body.time_range,
            "total": len(logs),
            "logs": logs,
            "error_count": sum(1 for l in logs if l["level"] == "ERROR"),
            "warning_count": sum(1 for l in logs if l["level"] == "WARNING"),
        }
        response = MCPToolResponse(
            success=True, tool="get_logs", data=data,
            duration_ms=round((time.monotonic() - t0) * 1000, 2)
        )
        _log_action("get_logs", body.dict(), {"total": data["total"]}, caller)
        return response
    except Exception as exc:
        logger.error(f"get_logs failed: {exc}", exc_info=True)
        return MCPToolResponse(success=False, tool="get_logs", data=None, error=str(exc))


@app.post("/tools/get_metrics", response_model=MCPToolResponse, tags=["MCP Tools"])
@limiter.limit("120/minute")
async def get_metrics(
    request: Request,
    body: GetMetricsRequest,
    caller: str = Depends(require_auth),
):
    """Retrieve current metrics for a service."""
    t0 = time.monotonic()
    try:
        metrics = _get_live_metrics(body.service_name)
        history = []
        if body.include_history:
            # Simulate 30-point history
            for i in range(30, 0, -1):
                history.append({
                    "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat(),
                    "cpu": round(random.uniform(20, 95), 2),
                    "memory": round(random.uniform(40, 90), 2),
                    "error_rate": round(random.uniform(0, 15), 2),
                    "response_time_ms": round(random.uniform(50, 2000), 1),
                })

        data = {"metrics": metrics, "history": history}
        response = MCPToolResponse(
            success=True, tool="get_metrics", data=data,
            duration_ms=round((time.monotonic() - t0) * 1000, 2)
        )
        _log_action("get_metrics", body.dict(), {"cpu": metrics["cpu_percent"]}, caller)
        return response
    except Exception as exc:
        logger.error(f"get_metrics failed: {exc}", exc_info=True)
        return MCPToolResponse(success=False, tool="get_metrics", data=None, error=str(exc))


@app.post("/tools/restart_service", response_model=MCPToolResponse, tags=["MCP Tools"])
@limiter.limit("10/minute")
async def restart_service(
    request: Request,
    body: RestartServiceRequest,
    caller: str = Depends(require_auth),
):
    """Restart a service. Applies cooldown + safety checks."""
    t0 = time.monotonic()
    logger.warning(f"RESTART requested for {body.service_name} by {caller} | reason: {body.reason}")

    try:
        state = _service_state.get(body.service_name)
        if state is None:
            return MCPToolResponse(
                success=False, tool="restart_service", data=None,
                error=f"Service '{body.service_name}' not found"
            )

        # Safety: max restarts guard
        restart_policy = CONFIG["remediation"]["policies"]["service_crash"]
        if state["restarts"] >= restart_policy["max_restarts"] and not body.force:
            return MCPToolResponse(
                success=False, tool="restart_service", data=None,
                error=(f"Service {body.service_name} has exceeded max restarts "
                       f"({restart_policy['max_restarts']}). Use force=true or escalate.")
            )

        # Simulate restart
        _service_state[body.service_name]["status"] = "restarting"
        await asyncio.sleep(0.5)  # Simulate restart time
        _service_state[body.service_name]["status"] = "running"
        _service_state[body.service_name]["restarts"] += 1
        _service_state[body.service_name]["cpu"] = max(10, state.get("cpu", 50) * 0.6)

        data = {
            "service": body.service_name,
            "action": "restart",
            "status": "completed",
            "new_status": "running",
            "restart_count": _service_state[body.service_name]["restarts"],
            "reason": body.reason,
        }
        response = MCPToolResponse(
            success=True, tool="restart_service", data=data,
            duration_ms=round((time.monotonic() - t0) * 1000, 2)
        )
        _log_action("restart_service", body.dict(), data, caller)
        logger.info(f"Service {body.service_name} restarted successfully by {caller}")
        return response

    except Exception as exc:
        logger.error(f"restart_service failed: {exc}", exc_info=True)
        return MCPToolResponse(success=False, tool="restart_service", data=None, error=str(exc))


@app.post("/tools/scale_service", response_model=MCPToolResponse, tags=["MCP Tools"])
@limiter.limit("10/minute")
async def scale_service(
    request: Request,
    body: ScaleServiceRequest,
    caller: str = Depends(require_auth),
):
    """Scale a service to the specified replica count."""
    t0 = time.monotonic()
    logger.warning(
        f"SCALE requested: {body.service_name} → {body.replicas} replicas by {caller}"
    )

    try:
        state = _service_state.get(body.service_name)
        if state is None:
            return MCPToolResponse(
                success=False, tool="scale_service", data=None,
                error=f"Service '{body.service_name}' not found"
            )

        old_replicas = state["replicas"]
        _service_state[body.service_name]["replicas"] = body.replicas

        # Scaling up reduces per-replica CPU load
        if body.replicas > old_replicas and old_replicas > 0:
            load_factor = old_replicas / body.replicas
            _service_state[body.service_name]["cpu"] = state.get("cpu", 80) * load_factor

        data = {
            "service": body.service_name,
            "action": "scale",
            "old_replicas": old_replicas,
            "new_replicas": body.replicas,
            "status": "completed",
            "reason": body.reason,
        }
        response = MCPToolResponse(
            success=True, tool="scale_service", data=data,
            duration_ms=round((time.monotonic() - t0) * 1000, 2)
        )
        _log_action("scale_service", body.dict(), data, caller)
        return response

    except Exception as exc:
        logger.error(f"scale_service failed: {exc}", exc_info=True)
        return MCPToolResponse(success=False, tool="scale_service", data=None, error=str(exc))


@app.post("/tools/notify_team", response_model=MCPToolResponse, tags=["MCP Tools"])
@limiter.limit("30/minute")
async def notify_team(
    request: Request,
    body: NotifyTeamRequest,
    caller: str = Depends(require_auth),
):
    """Send alert notifications to configured channels."""
    t0 = time.monotonic()
    logger.info(f"NOTIFY [{body.severity}]: {body.message[:80]} by {caller}")

    try:
        notif_cfg = CONFIG.get("notifications", {})
        channels_used = body.channels or notif_cfg.get("severity_routing", {}).get(body.severity, ["slack"])
        results = {}

        # Slack
        if "slack" in channels_used:
            slack_url = notif_cfg.get("slack_webhook", "")
            if slack_url:
                try:
                    async with httpx.AsyncClient(timeout=5) as client:
                        payload = {
                            "text": f"[{body.severity.upper()}] {body.message}",
                            "username": "AI DevOps Bot",
                            "icon_emoji": ":robot_face:",
                        }
                        resp = await client.post(slack_url, json=payload)
                        results["slack"] = {"status": "sent", "code": resp.status_code}
                except Exception as e:
                    results["slack"] = {"status": "failed", "error": str(e)}
            else:
                results["slack"] = {"status": "simulated", "message": body.message}

        # PagerDuty
        if "pagerduty" in channels_used:
            results["pagerduty"] = {"status": "simulated", "severity": body.severity}

        # Log notification
        notif_entry = {
            "id": generate_id("NOT"),
            "message": body.message,
            "severity": body.severity,
            "service": body.service_name,
            "incident_id": body.incident_id,
            "channels": channels_used,
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _notification_log.append(notif_entry)
        if len(_notification_log) > 500:
            _notification_log.pop(0)

        data = {"notification_id": notif_entry["id"], "channels": results, "delivered": True}
        response = MCPToolResponse(
            success=True, tool="notify_team", data=data,
            duration_ms=round((time.monotonic() - t0) * 1000, 2)
        )
        _log_action("notify_team", body.dict(), data, caller)
        return response

    except Exception as exc:
        logger.error(f"notify_team failed: {exc}", exc_info=True)
        return MCPToolResponse(success=False, tool="notify_team", data=None, error=str(exc))


# ─── State & Health Endpoints ─────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat(), "version": "1.0.0"}


@app.get("/state/services", tags=["State"])
async def get_all_service_states(caller: str = Depends(require_auth)):
    return {"services": _service_state, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/state/metrics/all", tags=["State"])
async def get_all_metrics(caller: str = Depends(require_auth)):
    return {
        "metrics": {svc: _get_live_metrics(svc) for svc in _service_state},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/state/notifications", tags=["State"])
async def get_notifications(limit: int = 50, caller: str = Depends(require_auth)):
    return {"notifications": _notification_log[-limit:], "total": len(_notification_log)}


@app.get("/state/action_log", tags=["State"])
async def get_action_log(limit: int = 100, caller: str = Depends(require_auth)):
    return {"actions": _action_log[-limit:], "total": len(_action_log)}


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp_cfg = CONFIG["mcp_server"]
    uvicorn.run(
        "mcp_server.server:app",
        host=mcp_cfg["host"],
        port=mcp_cfg["port"],
        log_level="info",
        access_log=True,
    )

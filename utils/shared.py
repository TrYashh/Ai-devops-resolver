"""
utils/shared.py — Shared utilities: config, logging, models, helpers
"""

import os
import json
import time
import logging
import logging.handlers
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pathlib import Path
import uuid

import yaml
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────────────────────

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """Load YAML config with environment variable interpolation."""

    with open(path, "r") as f:
        raw = f.read()

    import re

    def replace(match):
        expr = match.group(1)

        if ":-" in expr:
            var, default = expr.split(":-", 1)
            return os.environ.get(var.strip(), default.strip())

        return os.environ.get(expr.strip(), "")

    raw = re.sub(r"\$\{([^}]+)\}", replace, raw)

    return yaml.safe_load(raw)


# ─────────────────────────────────────────────────────────────
# JSON LOG FORMATTER
# ─────────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:

        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


# ─────────────────────────────────────────────────────────────
# LOGGER SETUP
# ─────────────────────────────────────────────────────────────

def setup_logger(name: str, config: Dict[str, Any]) -> logging.Logger:

    log_cfg = config.get("logging", {})

    level = getattr(logging, log_cfg.get("level", "INFO"))

    log_dir = Path("/logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / f"{name}.log"

    logger = logging.getLogger(name)

    logger.setLevel(level)

    if not logger.handlers:

        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename=log_file,
            when="midnight",
            backupCount=10,
            encoding="utf-8",
        )

        file_handler.setFormatter(JSONFormatter())

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


# ─────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────

class Severity(str, Enum):

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class ActionType(str, Enum):

    RESTART_SERVICE = "restart_service"
    SCALE_SERVICE = "scale_service"
    NOTIFY_TEAM = "notify_team"
    GET_LOGS = "get_logs"
    GET_METRICS = "get_metrics"
    NO_ACTION = "no_action"


class ActionStatus(str, Enum):

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


# ─────────────────────────────────────────────────────────────
# METRIC MODELS
# ─────────────────────────────────────────────────────────────

class ServiceMetrics(BaseModel):

    service_name: str

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_mb: float = 0.0

    error_rate: float = 0.0
    request_rate: float = 0.0

    response_time_ms: float = 0.0

    restart_count: int = 0

    uptime_seconds: float = 0.0

    status: str = "unknown"

    replicas: int = 1
    healthy_replicas: int = 1


class LogEntry(BaseModel):

    service_name: str

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    level: str = "INFO"

    message: str

    trace_id: Optional[str] = None

    extra: Dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# INCIDENT MODEL
# ─────────────────────────────────────────────────────────────

class Incident(BaseModel):

    id: str

    service_name: str

    title: str

    description: str

    severity: Severity

    status: IncidentStatus = IncidentStatus.OPEN

    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    resolved_at: Optional[datetime] = None

    anomaly_type: str

    metrics_snapshot: Optional[ServiceMetrics] = None

    action_taken: Optional[str] = None

    root_cause: Optional[str] = None

    tags: List[str] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# AGENT ACTION MODEL
# ─────────────────────────────────────────────────────────────

class AgentAction(BaseModel):

    id: str

    incident_id: Optional[str] = None

    service_name: str

    action_type: ActionType

    parameters: Dict[str, Any] = Field(default_factory=dict)

    reasoning: str

    status: ActionStatus = ActionStatus.PENDING

    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    completed_at: Optional[datetime] = None

    result: Optional[str] = None

    error: Optional[str] = None

    autonomous: bool = True


class AnomalyDetectionResult(BaseModel):

    service_name: str

    anomalies: List[Dict[str, Any]] = Field(default_factory=list)

    overall_severity: Optional[Severity] = None

    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)

    analysis_summary: str = ""


# ─────────────────────────────────────────────────────────────
# COOLDOWN TRACKER
# ─────────────────────────────────────────────────────────────

class CooldownTracker:

    def __init__(self):

        self._last_action: Dict[str, float] = {}

        self._action_counts: Dict[str, List[float]] = {}

    def is_cooling_down(self, service: str, action: str, cooldown_sec: int) -> bool:

        key = f"{service}:{action}"

        last = self._last_action.get(key, 0)

        return (time.time() - last) < cooldown_sec

    def record(self, service: str, action: str):

        key = f"{service}:{action}"

        self._last_action[key] = time.time()

        self._action_counts.setdefault(key, []).append(time.time())

    def action_count_last_hour(self, service: str, action: str) -> int:

        key = f"{service}:{action}"

        cutoff = time.time() - 3600

        counts = [t for t in self._action_counts.get(key, []) if t > cutoff]

        self._action_counts[key] = counts

        return len(counts)


# ─────────────────────────────────────────────────────────────
# RETRY DECORATOR
# ─────────────────────────────────────────────────────────────

def retry(max_attempts: int = 3, delay: float = 2.0, backoff: float = 2.0):

    import functools
    import asyncio

    def decorator(fn):

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):

            attempt = 0
            current_delay = delay

            last_exc = None

            while attempt < max_attempts:

                try:
                    return await fn(*args, **kwargs)

                except Exception as exc:

                    last_exc = exc

                    attempt += 1

                    if attempt < max_attempts:

                        await asyncio.sleep(current_delay)

                        current_delay *= backoff

            raise RuntimeError(
                f"All {max_attempts} attempts failed: {last_exc}"
            ) from last_exc

        return wrapper

    return decorator


# ─────────────────────────────────────────────────────────────
# ID GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_id(prefix: str = "") -> str:

    uid = str(uuid.uuid4())[:8].upper()

    return f"{prefix}-{uid}" if prefix else uid
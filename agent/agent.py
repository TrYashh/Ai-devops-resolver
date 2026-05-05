"""
agent/agent.py — Autonomous AI DevOps Agent
Analyzes metrics + logs → Detects anomalies → Plans actions → Executes via MCP
Uses Claude (Anthropic API) for intelligent reasoning.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from openai import OpenAI
from pydantic import BaseModel

from agent.anomaly_detector import AnomalyDetector
import logging

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.shared import (
    load_config, setup_logger,
    ServiceMetrics, Incident, AgentAction,
    Severity, IncidentStatus, ActionType, ActionStatus,
    CooldownTracker, generate_id, retry,
    AnomalyDetectionResult,
)

CONFIG = load_config(os.path.join(Path(__file__).parent.parent, "config.yaml"))
logger = setup_logger("ai_agent", CONFIG)

AGENT_CFG   = CONFIG["ai_agent"]
THRESHOLDS  = CONFIG["thresholds"]
POLICIES    = CONFIG["remediation"]["policies"]
MCP_URL     = f"http://mcp-server:{CONFIG['mcp_server']['port']}"
MCP_API_KEY = CONFIG["mcp_server"].get("api_key", "dev-api-key-change-me")


# ─── MCP Client ───────────────────────────────────────────────────────────────

class MCPClient:
    """Async HTTP client for calling MCP server tools."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    @retry(max_attempts=3, delay=2.0, backoff=2.0)
    async def call_tool(self, tool: str, payload: Dict) -> Dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/tools/{tool}",
                json=payload,
                headers=self.headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def get_metrics(self, service: str, include_history: bool = False) -> Dict:
        return await self.call_tool("get_metrics", {
            "service_name": service,
            "include_history": include_history,
        })

    async def get_logs(self, service: str, time_range: str = "30m", limit: int = 50) -> Dict:
        return await self.call_tool("get_logs", {
            "service_name": service,
            "time_range": time_range,
            "limit": limit,
        })

    async def restart_service(self, service: str, reason: str, force: bool = False) -> Dict:
        return await self.call_tool("restart_service", {
            "service_name": service,
            "reason": reason,
            "force": force,
        })

    async def scale_service(self, service: str, replicas: int, reason: str) -> Dict:
        return await self.call_tool("scale_service", {
            "service_name": service,
            "replicas": replicas,
            "reason": reason,
        })

    async def notify_team(self, message: str, severity: str,
                          service: Optional[str] = None,
                          incident_id: Optional[str] = None) -> Dict:
        return await self.call_tool("notify_team", {
            "message": message,
            "severity": severity,
            "service_name": service,
            "incident_id": incident_id,
        })

    async def get_all_metrics(self) -> Dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.base_url}/state/metrics/all",
                headers=self.headers,
            )
            resp.raise_for_status()
            return resp.json()


# ─── AI Decision Engine ───────────────────────────────────────────────────────

class AIDecisionEngine:
    """Uses Claude to reason about incidents and decide corrective actions."""

    SYSTEM_PROMPT = """You are an expert DevOps SRE AI agent responsible for autonomous incident resolution.
Your role:
1. Analyze infrastructure metrics and logs
2. Identify root causes of anomalies
3. Decide the best corrective action using safe, minimal-blast-radius principles
4. Provide clear reasoning for every decision

Safety rules you MUST follow:
- Never restart a service more than 3 times in 10 minutes without escalating to humans
- Always notify the team for CRITICAL incidents
- Prefer scaling over restarting when CPU is the issue
- Never scale below 1 replica for critical services
- When uncertain, notify_team instead of taking destructive action

You respond ONLY in JSON with this exact schema:
{
  "root_cause": "brief analysis of what is causing the issue",
  "confidence": 0.0-1.0,
  "recommended_actions": [
    {
      "action": "restart_service|scale_service|notify_team|no_action",
      "service_name": "...",
      "parameters": {"replicas": 4} or {},
      "priority": 1,
      "reasoning": "why this action",
      "estimated_impact": "what this will fix"
    }
  ],
  "escalate_to_human": true|false,
  "escalation_reason": "...",
  "summary": "one-line summary for incident ticket"
}"""

    def __init__(self):
        self.client = OpenAI(
            api_key=os.environ.get("GEMINI_API_KEY", ""),
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        )

    async def analyze(
        self,
        service: str,
        metrics: Dict,
        logs: List[Dict],
        anomalies: List[Dict],
        history: Optional[List[Dict]] = None,
    ) -> Dict:
        """Call Claude to analyze an incident and recommend actions."""

        error_logs = [l for l in logs if l.get("level") in ("ERROR", "WARNING")][:20]

        user_prompt = f"""
## Incident Analysis Request

**Service**: {service}
**Timestamp**: {datetime.now(timezone.utc).isoformat()}

### Current Metrics
```json
{json.dumps(metrics, indent=2, default=str)}
```

### Detected Anomalies
```json
{json.dumps(anomalies, indent=2, default=str)}
```

### Recent Error/Warning Logs (last 20)
```json
{json.dumps(error_logs, indent=2, default=str)}
```

### Metric History (last 30 mins)
```json
{json.dumps((history or [])[-10:], indent=2, default=str)}
```

Analyze this incident. Determine the root cause and provide specific remediation actions.
"""

        try:
            response = self.client.chat.completions.create(
                model=AGENT_CFG.get("model", "gemini-2.0-flash"),
                max_tokens=AGENT_CFG.get("max_tokens", 2048),
                temperature=AGENT_CFG.get("temperature", 0.2),
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            text = response.choices[0].message.content.strip()
            # Strip markdown fences if present
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"AI response parse error: {e}")
            return self._fallback_decision(anomalies, service)
        except Exception as e:
            logger.error(f"AI API call failed: {e}", exc_info=True)
            return self._fallback_decision(anomalies, service)

    def _fallback_decision(self, anomalies: List[Dict], service: str) -> Dict:
        """Rule-based fallback when AI API is unavailable."""
        actions = []
        for a in anomalies:
            hint = a.get("action_hint")
            if hint == ActionType.SCALE_SERVICE:
                actions.append({
                    "action": "scale_service",
                    "service_name": service,
                    "parameters": {"replicas": 4},
                    "priority": 1,
                    "reasoning": f"Rule-based fallback: {a['message']}",
                    "estimated_impact": "Distribute load across more replicas",
                })
            elif hint == ActionType.RESTART_SERVICE:
                actions.append({
                    "action": "restart_service",
                    "service_name": service,
                    "parameters": {},
                    "priority": 1,
                    "reasoning": f"Rule-based fallback: {a['message']}",
                    "estimated_impact": "Clear memory/process state",
                })
            else:
                actions.append({
                    "action": "notify_team",
                    "service_name": service,
                    "parameters": {},
                    "priority": 2,
                    "reasoning": f"Rule-based fallback: {a['message']}",
                    "estimated_impact": "Human review required",
                })
        return {
            "root_cause": "Rule-based analysis (AI unavailable)",
            "confidence": 0.6,
            "recommended_actions": actions,
            "escalate_to_human": any(a["severity"] == Severity.CRITICAL for a in anomalies),
            "escalation_reason": "AI engine offline — manual review required",
            "summary": f"Anomalies detected in {service}: " + ", ".join(a["type"] for a in anomalies),
        }


# ─── Main Agent Orchestrator ──────────────────────────────────────────────────

class IncidentAutoResolver:
    """Main orchestrator: collects → detects → decides → executes → verifies → notifies."""

    def __init__(self):
        self.mcp = MCPClient(MCP_URL, MCP_API_KEY)
        self.detector = AnomalyDetector()
        self.ai_engine = AIDecisionEngine()
        self.cooldown = CooldownTracker()

        self.autonomous_mode: bool = AGENT_CFG.get("autonomous_mode", True)
        self.incidents: Dict[str, Incident] = {}
        self.actions: List[AgentAction] = []
        self.suggestions: List[Dict] = []  # For suggestion mode
        self._running = False
        self._action_count_hour = 0
        self._hour_start = time.time()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self):
        self._running = True
        logger.info("AI Agent started", extra={"mode": "autonomous" if self.autonomous_mode else "suggestion"})
        await asyncio.gather(
            self._monitor_loop(),
            self._cleanup_loop(),
        )

    async def stop(self):
        self._running = False
        logger.info("AI Agent stopping")

    # ── Main Monitor Loop ─────────────────────────────────────────────────────

    async def _monitor_loop(self):
        interval = AGENT_CFG.get("analysis_interval_seconds", 30)
        services = [s["name"] for s in CONFIG["monitoring"]["services"]]

        while self._running:
            try:
                logger.debug("Starting monitoring cycle")
                tasks = [self._analyze_service(svc) for svc in services]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for svc, result in zip(services, results):
                    if isinstance(result, Exception):
                        logger.error(f"Analysis failed for {svc}: {result}")
            except Exception as e:
                logger.error(f"Monitor loop error: {e}", exc_info=True)
            await asyncio.sleep(interval)

    async def _cleanup_loop(self):
        """Resolve stale incidents, reset hourly counters."""
        while self._running:
            await asyncio.sleep(60)
            # Reset hourly action counter
            if time.time() - self._hour_start > 3600:
                self._action_count_hour = 0
                self._hour_start = time.time()

    # ── Per-Service Analysis ──────────────────────────────────────────────────

    async def _analyze_service(self, service: str):
        """Full pipeline: metrics → anomalies → AI decision → action."""
        # 1. Collect metrics + logs
        metrics_resp = await self.mcp.get_metrics(service, include_history=True)
        metrics = metrics_resp.get("data", {}).get("metrics", {})
        history = metrics_resp.get("data", {}).get("history", [])

        # 2. Rule-based anomaly detection
        cpu = metrics.get("cpu_percent", 0)
        memory = metrics.get("memory_percent", 0)
        disk = metrics.get("disk_io", 0)
        network = metrics.get("network_io", 0)
        error_rate = metrics.get("error_rate", 0)
        latency = metrics.get("response_time_ms", 0)

        is_anomaly = self.detector.is_anomaly(
            cpu, memory, disk, network, error_rate, latency
        )

        anomalies = []

        if is_anomaly:
            anomalies.append({
                "type": "ml_detected_anomaly",
                "severity": Severity.CRITICAL,
                "value": cpu,
                "message": "ML model detected abnormal system behavior",
                "action_hint": ActionType.RESTART_SERVICE
            })

        # 3. Get logs for context
        logs_resp = await self.mcp.get_logs(service, time_range="30m", limit=50)
        logs = logs_resp.get("data", {}).get("logs", [])

        # 4. AI reasoning
        logger.info(f"Anomalies detected on {service}: {[a['type'] for a in anomalies]}")
        ai_decision = await self.ai_engine.analyze(service, metrics, logs, anomalies, history)

        # 5. Create/update incident
        incident = self._upsert_incident(service, anomalies, ai_decision, metrics)

        # 6. Execute or suggest
        if self.autonomous_mode:
            await self._execute_plan(incident, ai_decision, metrics)
        else:
            self._record_suggestion(incident, ai_decision)

    # ── Incident Management ───────────────────────────────────────────────────

    def _upsert_incident(
        self, service: str, anomalies: List[Dict],
        ai_decision: Dict, metrics: Dict
    ) -> Incident:
        existing_key = f"{service}:{anomalies[0]['type']}"
        if existing_key in self.incidents:
            incident = self.incidents[existing_key]
            incident.status = IncidentStatus.IN_PROGRESS
            return incident

        severity = max(
            (a["severity"] for a in anomalies),
            key=lambda s: [Severity.INFO, Severity.WARNING, Severity.CRITICAL].index(s)
        )
        incident = Incident(
            id=generate_id("INC"),
            service_name=service,
            title=ai_decision.get("summary", f"Anomaly detected: {anomalies[0]['type']}"),
            description=ai_decision.get("root_cause", ""),
            severity=severity,
            anomaly_type=anomalies[0]["type"],
            metrics_snapshot=ServiceMetrics(**{
                k: v for k, v in metrics.items()
                if k in ServiceMetrics.__fields__
            }) if metrics else None,
            tags=[a["type"] for a in anomalies],
        )
        self.incidents[existing_key] = incident
        logger.warning(f"New incident: {incident.id} | {service} | {severity}")
        return incident

    def _maybe_resolve_incident(self, service: str):
        for key, incident in list(self.incidents.items()):
            if key.startswith(f"{service}:") and incident.status != IncidentStatus.RESOLVED:
                incident.status = IncidentStatus.RESOLVED
                incident.resolved_at = datetime.now(timezone.utc)
                logger.info(f"Incident {incident.id} resolved for {service}")

    # ── Action Execution ──────────────────────────────────────────────────────

    async def _execute_plan(self, incident: Incident, ai_decision: Dict, metrics: Dict):
        """Execute AI-recommended actions with safety gates."""
        # Rate limit guard
        max_per_hour = AGENT_CFG.get("max_actions_per_hour", 20)
        if self._action_count_hour >= max_per_hour:
            logger.warning("Hourly action limit reached — skipping autonomous action")
            await self.mcp.notify_team(
                f"[RATE LIMIT] Hourly action limit ({max_per_hour}) reached. Manual review required.",
                "warning", service_name=incident.service_name, incident_id=incident.id,
            )
            return

        # Sort actions by priority
        planned_actions = sorted(
            ai_decision.get("recommended_actions", []),
            key=lambda a: a.get("priority", 99),
        )

        for plan in planned_actions:
            action_type = plan.get("action")
            svc = plan.get("service_name", incident.service_name)
            params = plan.get("parameters", {})
            reasoning = plan.get("reasoning", "")

            # Cooldown check
            cooldown_sec = POLICIES.get(
                {"restart_service": "service_crash", "scale_service": "high_cpu"}.get(action_type, ""),
                {}
            ).get("cooldown_seconds", 120)

            if self.cooldown.is_cooling_down(svc, action_type, cooldown_sec):
                remaining = cooldown_sec - (time.time() - self.cooldown._last_action.get(f"{svc}:{action_type}", 0))
                logger.info(f"Cooldown active for {svc}:{action_type} — {remaining:.0f}s remaining")
                continue

            action = AgentAction(
                id=generate_id("ACT"),
                incident_id=incident.id,
                service_name=svc,
                action_type=ActionType(action_type) if action_type in ActionType.__members__.values() else ActionType.NOTIFY_TEAM,
                parameters=params,
                reasoning=reasoning,
                autonomous=True,
            )
            self.actions.append(action)

            success = await self._execute_action(action, incident, metrics)
            self.cooldown.record(svc, action_type)
            self._action_count_hour += 1

            if not success:
                logger.error(f"Action {action.id} failed — escalating")
                await self._escalate(incident, action)

        # Always notify on critical
        if incident.severity == Severity.CRITICAL:
            await self.mcp.notify_team(
                f"[CRITICAL] {incident.title}\nService: {incident.service_name}\n"
                f"Root cause: {ai_decision.get('root_cause', 'Unknown')}",
                severity=Severity.CRITICAL,
                service_name=incident.service_name,
                incident_id=incident.id,
            )

        # Escalate if AI recommends it
        if ai_decision.get("escalate_to_human"):
            incident.status = IncidentStatus.ESCALATED
            await self.mcp.notify_team(
                f"[ESCALATION] {incident.id} — {ai_decision.get('escalation_reason', '')}",
                severity=Severity.CRITICAL,
                service_name=incident.service_name,
                incident_id=incident.id,
            )

    async def _execute_action(
        self, action: AgentAction, incident: Incident, metrics: Dict
    ) -> bool:
        action.status = ActionStatus.RUNNING
        logger.info(f"Executing {action.action_type} on {action.service_name} | {action.reasoning[:80]}")

        try:
            result = None
            if action.action_type == ActionType.RESTART_SERVICE:
                result = await self.mcp.restart_service(
                    action.service_name, reason=action.reasoning
                )
            elif action.action_type == ActionType.SCALE_SERVICE:
                current_replicas = int(metrics.get("replicas", 1))
                target = action.parameters.get("replicas", current_replicas + 2)
                result = await self.mcp.scale_service(
                    action.service_name, replicas=target, reason=action.reasoning
                )
            elif action.action_type == ActionType.NOTIFY_TEAM:
                result = await self.mcp.notify_team(
                    f"[{incident.severity.upper()}] {incident.title}\n{action.reasoning}",
                    severity=incident.severity,
                    service_name=action.service_name,
                    incident_id=incident.id,
                )
            elif action.action_type == ActionType.NO_ACTION:
                action.status = ActionStatus.SKIPPED
                action.result = "No action required"
                return True

            success = result.get("success", False) if result else False
            action.status = ActionStatus.SUCCESS if success else ActionStatus.FAILED
            action.result = json.dumps(result.get("data", {}), default=str)[:500] if result else None
            action.completed_at = datetime.now(timezone.utc)
            incident.action_taken = str(action.action_type)
            return success

        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
            action.completed_at = datetime.now(timezone.utc)
            logger.error(f"Action execution error: {e}", exc_info=True)
            return False

    async def _escalate(self, incident: Incident, failed_action: AgentAction):
        incident.status = IncidentStatus.ESCALATED
        await self.mcp.notify_team(
            f"[AUTO-ESCALATION] Action {failed_action.id} ({failed_action.action_type}) "
            f"failed on {incident.service_name}. Human intervention required.\n"
            f"Incident: {incident.id} | {incident.title}",
            severity=Severity.CRITICAL,
            service_name=incident.service_name,
            incident_id=incident.id,
        )

    def _record_suggestion(self, incident: Incident, ai_decision: Dict):
        """In suggestion mode, log recommendations without executing."""
        suggestion = {
            "incident_id": incident.id,
            "service": incident.service_name,
            "severity": incident.severity,
            "recommended_actions": ai_decision.get("recommended_actions", []),
            "root_cause": ai_decision.get("root_cause"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.suggestions.append(suggestion)
        logger.info(f"Suggestion recorded (suggestion mode): {incident.id}")

    # ── Public API ────────────────────────────────────────────────────────────

    def get_status(self) -> Dict:
        return {
            "running": self._running,
            "autonomous_mode": self.autonomous_mode,
            "open_incidents": [
                i.dict() for i in self.incidents.values()
                if i.status != IncidentStatus.RESOLVED
            ],
            "recent_actions": [a.dict() for a in self.actions[-50:]],
            "suggestions": self.suggestions[-20:],
            "action_count_this_hour": self._action_count_hour,
            "total_incidents": len(self.incidents),
        }

    def set_autonomous_mode(self, enabled: bool):
        self.autonomous_mode = enabled
        logger.info(f"Autonomous mode {'ENABLED' if enabled else 'DISABLED'}")

    async def trigger_manual_action(
        self, action_type: str, service_name: str,
        parameters: Dict, reason: str
    ) -> Dict:
        """Allow dashboard to trigger manual actions."""
        action = AgentAction(
            id=generate_id("MAN"),
            service_name=service_name,
            action_type=ActionType(action_type),
            parameters=parameters,
            reasoning=f"[MANUAL] {reason}",
            autonomous=False,
        )
        self.actions.append(action)
        # Create a dummy incident for context
        dummy_incident = Incident(
            id=generate_id("INC"),
            service_name=service_name,
            title=f"Manual action: {action_type}",
            description=reason,
            severity=Severity.WARNING,
            anomaly_type="manual_trigger",
        )
        metrics_resp = await self.mcp.get_metrics(service_name)
        metrics = metrics_resp.get("data", {}).get("metrics", {})
        success = await self._execute_action(action, dummy_incident, metrics)
        return {"success": success, "action": action.dict()}


# ─── Entrypoint ───────────────────────────────────────────────────────────────

async def main():
    agent = IncidentAutoResolver()
    try:
        await agent.start()
    except KeyboardInterrupt:
        await agent.stop()

if __name__ == "__main__":
    asyncio.run(main())

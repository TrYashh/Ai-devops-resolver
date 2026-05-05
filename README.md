# AI DevOps Incident Auto-Resolver

An enterprise-grade autonomous AI system for infrastructure monitoring, anomaly detection, and automated incident remediation using Claude AI + Model Context Protocol (MCP).

## Quick Start

```bash
cp .env.example .env
# Fill in ANTHROPIC_API_KEY, JWT_SECRET, SLACK_WEBHOOK_URL
docker compose up --build
```

Access points:
- Dashboard:     http://localhost:3000
- Backend API:   http://localhost:8000/docs
- MCP Server:    http://localhost:8001/docs
- Prometheus:    http://localhost:9090
- Grafana:       http://localhost:3001  (admin / from .env)
- Alertmanager:  http://localhost:9093

## Architecture

```
React Dashboard (3000)
    ↕ WebSocket + REST
FastAPI Backend (8000) ←→ Redis (6379)
    ↕
MCP Tool Server (8001) [JWT + API-Key auth]
    ↕
AI Agent (Claude Sonnet)
    ├── Anomaly Detector (rule-based, fast)
    ├── AI Decision Engine (Claude API, rich reasoning)
    └── Incident Manager (cooldown, rate-limit, escalation)
    ↕
Prometheus (9090) + Grafana (3001) + Alertmanager (9093)
    ↕
Services: api-gateway · worker-svc · db-proxy · cache-svc
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `get_logs` | Fetch service logs with time range filter |
| `get_metrics` | Real-time CPU, memory, RPS, P99, error rate |
| `restart_service` | Rolling restart with safety guards |
| `scale_service` | Horizontal pod scaling with replica policy |
| `notify_team` | Slack + PagerDuty alerts with severity levels |

## AI Automation Flow

1. Agent polls metrics every 30s per service
2. Rule-based anomaly detector flags issues (fast path)
3. Claude API called with logs + metrics for root-cause analysis
4. Incident created/updated with priority ranking
5. Cooldown check + hourly rate limit (20 actions/hr default)
6. MCP tool executed (restart / scale / notify)
7. Result verified; incident resolved or escalated
8. WebSocket broadcasts updates to all dashboard clients

## Safety Controls

- Cooldown per service+action type (configurable in config.yaml)
- Max restarts before forced human escalation
- Hourly action rate cap (20/hr default)
- Suggestion mode (AI recommends, human approves)
- Emergency kill switch via dashboard

## Configuration

All thresholds, cooldowns, and policies in `config.yaml`:
- CPU/memory/error-rate alert thresholds
- Per-service remediation policies
- Notification channels (Slack, PagerDuty)
- Agent mode defaults

## File Structure

```
/frontend          React dashboard (Vite + TypeScript)
/backend           FastAPI REST + WebSocket API
/mcp_server        MCP tool server (JWT + API-key auth)
/agent             AI agent: detector + decision + resolver
/monitoring        Prometheus config + alert rules
/utils             Shared models, logger, retry utilities
config.yaml        All system configuration
docker-compose.yml Full stack deployment
requirements.txt   Python dependencies
```

# 🚀 AI DevOps Incident Auto-Resolver

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![React](https://img.shields.io/badge/React-Frontend-61dafb)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ed)
![Prometheus](https://img.shields.io/badge/Prometheus-Monitoring-orange)
![Grafana](https://img.shields.io/badge/Grafana-Visualization-f46800)
![Redis](https://img.shields.io/badge/Redis-Cache-red)
![ML](https://img.shields.io/badge/MachineLearning-IsolationForest-purple)

---

## 📌 Overview

AI DevOps Resolver is an AI-powered observability and automated incident remediation platform designed to monitor infrastructure health, detect anomalies using machine learning, visualize telemetry, and automate operational workflows.

The platform combines:

- 📊 Real-time monitoring
- 🤖 AI anomaly detection
- ⚡ Automated remediation
- 📈 Infrastructure observability
- 🐳 Dockerized distributed services
- 🖥️ Custom operational dashboard

This project simulates the architecture of modern observability platforms such as:

- Datadog
- New Relic
- Dynatrace
- Splunk Observability

---

# 🏗️ System Architecture

```text
                 ┌──────────────────────┐
                 │      User/Admin      │
                 └──────────┬───────────┘
                            │
                            ▼
             ┌────────────────────────────┐
             │ React Frontend Dashboard   │
             └───────────┬────────────────┘
                         │ REST API
                         ▼
               ┌───────────────────────┐
               │    FastAPI Backend    │
               └──────────┬────────────┘
                          │
      ┌───────────────────┼─────────────────────┐
      ▼                   ▼                     ▼
┌──────────────┐  ┌──────────────┐   ┌────────────────┐
│ AI Agent     │  │ MCP Server   │   │ Redis Cache    │
│ ML Detection │  │ Tool Control │   │ State Storage  │
└──────┬───────┘  └──────┬───────┘   └────────────────┘
       │                 │
       ▼                 ▼
     ┌─────────────────────────────┐
     │    Prometheus Monitoring    │
     └────────────┬────────────────┘
                  │
                  ▼
     ┌─────────────────────────────┐
     │ Node Exporter + Containers  │
     └─────────────────────────────┘
                  │
                  ▼
     ┌─────────────────────────────┐
     │         Grafana             │
     └─────────────────────────────┘
```

---

# ✨ Features

## 📊 Monitoring & Observability
- Real-time infrastructure monitoring
- Prometheus metrics collection
- Grafana dashboards
- Container telemetry monitoring
- Service health tracking

## 🤖 AI & Machine Learning
- Isolation Forest anomaly detection
- AI-driven incident analysis
- Automated anomaly alerts
- Intelligent remediation pipeline

## ⚡ Automation
- MCP tool orchestration
- Auto-remediation workflows
- Service restart simulation
- Alert escalation support

## 🖥️ Frontend Dashboard
- Custom React monitoring dashboard
- Service status cards
- Logs viewer
- AI alert visualization
- Metrics overview panel

## 🐳 Infrastructure
- Fully Dockerized architecture
- Multi-container orchestration
- Redis caching layer
- Distributed service design

---

# 🧠 Machine Learning Workflow

```text
Metrics Collection
        ↓
Training Dataset
        ↓
Isolation Forest Training
        ↓
Real-Time Prediction
        ↓
Anomaly Detection
        ↓
Alert + Remediation
```

---

# 📂 Project Structure

```text
ai-devops-resolver/
│
├── backend/                 # FastAPI backend APIs
├── frontend/                # React frontend dashboard
├── agent/                   # AI monitoring & anomaly engine
├── mcp_server/              # MCP orchestration server
├── monitoring/              # Prometheus + Alertmanager configs
├── logs/                    # Application logs
├── utils/                   # Shared utilities
│
├── docker-compose.yml
├── Dockerfile.backend
├── requirements.txt
├── config.yaml
└── README.md
```

---

# ⚙️ Tech Stack

| Layer | Technology |
|------|-------------|
| Frontend | React + Vite |
| Backend | FastAPI |
| Monitoring | Prometheus |
| Visualization | Grafana |
| AI Engine | Isolation Forest |
| ML Library | Scikit-learn |
| Containerization | Docker |
| Cache Layer | Redis |
| Metrics Export | Node Exporter |
| Alerts | Alertmanager |
| API Server | Uvicorn |

---

# 🔄 System Workflow

```text
Node Exporter
      ↓
Prometheus Metrics Collection
      ↓
AI Agent Analysis
      ↓
Anomaly Detection
      ↓
MCP Remediation Actions
      ↓
Frontend + Grafana Visualization
```

---

# 📸 Dashboard Preview

## 🖥️ Custom Frontend Dashboard

> Add screenshot here

```md
![Frontend Dashboard](assets/frontend.png)
```

---

## 📊 Grafana Monitoring

> Add screenshot here

```md
![Grafana Dashboard](assets/grafana.png)
```

---

## 📈 Prometheus Metrics

> Add screenshot here

```md
![Prometheus Metrics](assets/prometheus.png)
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/your-username/ai-devops-resolver.git
cd ai-devops-resolver
```

---

## Configure Environment Variables

Create `.env`

```env
MCP_API_KEY=your-api-key
JWT_SECRET=your-secret
GEMINI_API_KEY=your-gemini-key
GRAFANA_PASSWORD=admin123
```

---

## Run Entire Infrastructure

```bash
docker compose up --build
```

---

# 🌐 Services

| Service | URL |
|---|---|
| Frontend Dashboard | http://localhost:3000 |
| Grafana | http://localhost:3001 |
| Prometheus | http://localhost:9090 |
| Backend API | http://localhost:8000/docs |
| MCP Server | http://localhost:8001 |

---

# 🧪 Simulate Anomaly

Stress backend CPU:

```bash
docker exec -it resolver-backend python -c "while True: pass"
```

Observe:
- Grafana spikes
- Prometheus metrics
- AI anomaly detection
- Frontend alerts

---

# 📊 Monitoring Stack

## Prometheus
Responsible for:
- metrics scraping
- telemetry collection
- alert evaluation
- time-series storage

## Grafana
Responsible for:
- infrastructure visualization
- dashboards
- operational graphs
- telemetry analytics

---

# 🤖 AI Agent

The AI Agent continuously:
- monitors metrics
- analyzes infrastructure behavior
- detects anomalies
- triggers remediation workflows

The current implementation uses:
- Isolation Forest
- rule-based remediation
- telemetry analysis

---

# 🔐 Security

- JWT-based authentication
- MCP API key validation
- Docker isolated networking
- Environment variable secrets

---

# 🚀 Future Improvements

- Kubernetes integration
- Distributed tracing
- WebSocket live telemetry
- Advanced ML models
- Cloud deployment
- Role-based authentication
- Real-time log streaming
- AI incident summarization

---

# 👨‍💻 Author

### Yash Tripathi

AI/ML + Full Stack + Infrastructure Engineering

---

# ⭐ Project Goal

The goal of this project is to explore the intersection of:

- AI Ops
- Infrastructure Monitoring
- Observability
- Machine Learning
- Automated Incident Remediation

within a modern distributed architecture.

---

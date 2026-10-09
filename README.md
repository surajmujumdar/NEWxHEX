# 🛡️ VAJRA | AI Cybersecurity & Threat Intelligence Platform

An enterprise-grade, high-performance cybersecurity platform providing **AI Threat Intelligence, Real-Time Ransomware Tracking, Attack Surface Analysis, Global Threat Map, SOC SIEM Integration, and Autonomous Cyber Defense**.

---

## 🌟 Architecture & Highlights

```text
                             VAJRA CYBER DEFENSE PLATFORM
                                          │
       ┌──────────────────────────────────┴──────────────────────────────────┐
       │                                                                     │
  [ 🛡️ THREAT INTELLIGENCE MATRIX ]                                 [ 🌐 COMMAND & MONITORING ]
  • AI Threat Intelligence Scoring & Analytics                     • Monitored Companies & Assets
  • Live Ransomware Attack Tracking & Feed                         • Real-time Global Attack Map (WebGL)
  • APT Threat Actor Profiles & Tactics                            • Critical Security Alerts & News Feed
  • Targeted Sectors & Industry Intelligence                       • SOC Integration & Syslog Feeds
  • Domain Risk & SSL Pulse Telemetry                              • Executive Briefs & PDF Export
                                          │
                                  (ai_security.db)
```

- **Single Command Startup**: Boots the FastAPI backend (Port 8000) and Next.js frontend (Port 3000) seamlessly.
- **Dedicated Database**: `ai_security.db` for persistent company risk metrics, threat scores, notifications, and incident records.
- **Interactive REST API**: Complete Swagger UI and OpenAPI documentation at `http://localhost:8000/docs`.

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python 3.10+**
- **Node.js 18+** & **npm**

### 2. Launch Application
Run the universal launcher:
```bash
python run.py
```
*(Or on Windows: `start.bat` | On macOS/Linux: `./start.sh`)*

Then open your browser at:
👉 **`http://localhost:3000`**

Swagger REST API Documentation:
👉 **`http://localhost:8000/docs`**

---

## 🔑 Default Credentials

| Platform | Email | Password | Role |
| :--- | :--- | :--- | :--- |
| **VAJRA** | `admin@indigo.com` | `admin123` | Administrator |

---

## 📡 Key Endpoints

- **Web Dashboard**: `http://localhost:3000`
- **REST API Docs**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/api/health`
- **Threat Intelligence**: `http://localhost:8000/api/threat-intelligence`
- **Ransomware Stream**: `http://localhost:8000/api/ransomware`
- **SOC Integration**: `http://localhost:8000/api/soc`
- **Domain Analysis**: `http://localhost:8000/api/domain-analysis`

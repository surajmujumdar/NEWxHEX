import sys
import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import Response
from contextlib import asynccontextmanager
import logging
from logging.config import dictConfig
from dotenv import load_dotenv

# Ensure paths for VAJRA subsystem
BACKEND_DIR = Path(__file__).resolve().parent
VAJRA_DIR = BACKEND_DIR / "vajra"

# Load environment variables
load_dotenv(BACKEND_DIR / ".env")
load_dotenv(BACKEND_DIR.parent / ".env")

# Configure clean module paths:
for p in [str(BACKEND_DIR), str(VAJRA_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Configure structured logging
dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["default"],
    },
})

logger = logging.getLogger("vajra-platform")

# Import VAJRA Components
try:
    from database.database import engine as vajra_engine, Base as VajraBase, SessionLocal as VajraSessionLocal
    from models.user import User as VajraUser
    from auth.password_handler import hash_password as vajra_hash_password
    from websocket.websocket_manager import websocket_manager
    from routes import (
        auth as vajra_auth,
        dashboard as vajra_dashboard,
        threat as vajra_threat,
        ransomware as vajra_ransomware,
        news as vajra_news,
        reports as vajra_reports,
        ai as vajra_ai,
        alerts as vajra_alerts,
        threat_actors as vajra_threat_actors,
        industries as vajra_industries,
        notifications as vajra_notifications,
        domain as vajra_domain,
        domain_analysis as vajra_domain_analysis,
        companies as vajra_companies,
        soc as vajra_soc,
        data_sources as vajra_data_sources,
        repositories as vajra_repositories,
        hexstrike as vajra_hexstrike
    )
    from admin import routes as vajra_admin_routes
    from websocket.websocket_routes import router as websocket_router
    from scheduler.scheduler import scheduler as vajra_scheduler
    from middleware.rate_limit import limiter
    VAJRA_AVAILABLE = True
    logger.info("[VAJRA] Core modules imported successfully.")
except Exception as e:
    VAJRA_AVAILABLE = False
    logger.error(f"[VAJRA] Failed to import VAJRA modules: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Sequence
    logger.info("Initializing VAJRA Cybersecurity & Threat Intelligence Platform...")

    # Initialize VAJRA Subsystem
    if VAJRA_AVAILABLE:
        try:
            VajraBase.metadata.create_all(bind=vajra_engine)
            logger.info("[VAJRA] Database tables verified/created.")

            # Seed default admin user for VAJRA
            v_db = VajraSessionLocal()
            try:
                admin_user = v_db.query(VajraUser).filter(VajraUser.email == "admin@indigo.com").first()
                if not admin_user:
                    admin_user = VajraUser(
                        email="admin@indigo.com",
                        name="Admin User",
                        hashed_password=vajra_hash_password("admin123"),
                        role="Admin",
                        is_active=True
                    )
                    v_db.add(admin_user)
                    v_db.commit()
                    logger.info("[VAJRA] Default admin user seeded (admin@indigo.com).")
                else:
                    admin_user.hashed_password = vajra_hash_password("admin123")
                    admin_user.role = "Admin"
                    admin_user.is_active = True
                    v_db.commit()
            except Exception as v_err:
                logger.error(f"[VAJRA] Error verifying admin user: {v_err}")
                v_db.rollback()
            finally:
                v_db.close()

            # Start VAJRA Scheduler
            try:
                vajra_scheduler.start()
                logger.info("[VAJRA] Background scheduler started successfully.")
            except Exception as sch_err:
                logger.warning(f"[VAJRA] Scheduler warning: {sch_err}")

        except Exception as e:
            logger.error(f"[VAJRA] Database initialization error: {e}")

    logger.info("VAJRA Cybersecurity Platform fully operational.")
    yield

    # Shutdown Sequence
    logger.info("Shutting down VAJRA Cybersecurity Platform...")
    if VAJRA_AVAILABLE:
        try:
            vajra_scheduler.shutdown()
        except Exception:
            pass
        try:
            await websocket_manager.disconnect_all()
        except Exception:
            pass
    logger.info("VAJRA Platform shutdown complete.")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


app = FastAPI(
    title="VAJRA Cybersecurity & Threat Intelligence Platform",
    description="Enterprise AI-Powered Threat Intelligence, Attack Surface Monitoring, Ransomware Tracking & Cyber Defense",
    version="2.0.0",
    lifespan=lifespan
)

# Apply Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Configure Secure CORS
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

# Apply Rate Limiter state if available
if VAJRA_AVAILABLE:
    app.state.limiter = limiter

# ==========================================
# VAJRA API ROUTERS
# ==========================================
if VAJRA_AVAILABLE:
    app.include_router(vajra_auth.router, prefix="/api/auth", tags=["VAJRA Auth"])
    app.include_router(vajra_auth.router, prefix="/api/vajra/auth", tags=["VAJRA Auth (Namespaced)"])

    app.include_router(vajra_dashboard.router, prefix="/api/dashboard", tags=["VAJRA Dashboard"])
    app.include_router(vajra_dashboard.router, prefix="/api/vajra/dashboard", tags=["VAJRA Dashboard (Namespaced)"])

    app.include_router(vajra_threat.router, prefix="/api/threat-intelligence", tags=["VAJRA Threat Intelligence"])
    app.include_router(vajra_threat.router, prefix="/api/vajra/threat-intelligence", tags=["VAJRA Threat Intelligence (Namespaced)"])

    app.include_router(vajra_ransomware.router, prefix="/api/ransomware", tags=["VAJRA Ransomware"])
    app.include_router(vajra_ransomware.router, prefix="/api/vajra/ransomware", tags=["VAJRA Ransomware (Namespaced)"])

    app.include_router(vajra_news.router, prefix="/api/news", tags=["VAJRA News"])
    app.include_router(vajra_news.router, prefix="/api/vajra/news", tags=["VAJRA News (Namespaced)"])

    app.include_router(vajra_reports.router, prefix="/api/reports", tags=["VAJRA Reports"])
    app.include_router(vajra_reports.router, prefix="/api/vajra/reports", tags=["VAJRA Reports (Namespaced)"])

    app.include_router(vajra_ai.router, prefix="/api/ai", tags=["VAJRA AI"])
    app.include_router(vajra_ai.router, prefix="/api/vajra/ai", tags=["VAJRA AI (Namespaced)"])

    app.include_router(vajra_alerts.router, prefix="/api/alerts", tags=["VAJRA Alerts"])
    app.include_router(vajra_alerts.router, prefix="/api/vajra/alerts", tags=["VAJRA Alerts (Namespaced)"])

    app.include_router(vajra_threat_actors.router, prefix="/api/threat-intelligence/actors", tags=["VAJRA Threat Actors"])
    app.include_router(vajra_threat_actors.router, prefix="/api/vajra/threat-intelligence/actors", tags=["VAJRA Threat Actors (Namespaced)"])

    app.include_router(vajra_industries.router, prefix="/api/threat-intelligence/industries", tags=["VAJRA Industries"])
    app.include_router(vajra_industries.router, prefix="/api/vajra/threat-intelligence/industries", tags=["VAJRA Industries (Namespaced)"])

    app.include_router(vajra_notifications.router, prefix="/api/notifications", tags=["VAJRA Notifications"])
    app.include_router(vajra_notifications.router, prefix="/api/vajra/notifications", tags=["VAJRA Notifications (Namespaced)"])

    app.include_router(vajra_admin_routes.router, prefix="/api/admin", tags=["VAJRA Admin"])
    app.include_router(vajra_admin_routes.router, prefix="/api/vajra/admin", tags=["VAJRA Admin (Namespaced)"])

    app.include_router(vajra_domain.router, prefix="/api/domain-risk", tags=["VAJRA Domain Risk"])
    app.include_router(vajra_domain.router, prefix="/api/vajra/domain-risk", tags=["VAJRA Domain Risk (Namespaced)"])

    app.include_router(vajra_domain_analysis.router, prefix="/api/domain-analysis", tags=["VAJRA Domain Analysis"])
    app.include_router(vajra_domain_analysis.router, prefix="/api/vajra/domain-analysis", tags=["VAJRA Domain Analysis (Namespaced)"])

    app.include_router(vajra_companies.router, prefix="/api/companies", tags=["VAJRA Companies"])
    app.include_router(vajra_companies.router, prefix="/api/vajra/companies", tags=["VAJRA Companies (Namespaced)"])

    app.include_router(vajra_soc.router, prefix="/api/soc", tags=["VAJRA SOC"])
    app.include_router(vajra_soc.router, prefix="/api/vajra/soc", tags=["VAJRA SOC (Namespaced)"])

    app.include_router(vajra_data_sources.router, prefix="/api/data-sources", tags=["VAJRA Data Sources"])
    app.include_router(vajra_data_sources.router, prefix="/api/vajra/data-sources", tags=["VAJRA Data Sources (Namespaced)"])

    app.include_router(vajra_repositories.router, prefix="/api/repositories", tags=["VAJRA Repositories"])
    app.include_router(vajra_repositories.router, prefix="/api/vajra/repositories", tags=["VAJRA Repositories (Namespaced)"])

    app.include_router(vajra_hexstrike.router, prefix="/api/hexstrike", tags=["HexStrike AI MCP"])
    app.include_router(vajra_hexstrike.router, prefix="/api/vajra/hexstrike", tags=["HexStrike AI MCP (Namespaced)"])

    app.include_router(websocket_router)

# ==========================================
# VAJRA HEALTH & ROOT ENDPOINTS
# ==========================================
@app.get("/api/health")
@app.get("/health")
def vajra_health():
    return {
        "status": "healthy",
        "service": "VAJRA Cybersecurity & Threat Intelligence Platform",
        "version": "2.0.0",
        "database": "ai_security.db",
        "mode": "ONLINE",
        "vajra_status": "ONLINE" if VAJRA_AVAILABLE else "OFFLINE"
    }


@app.get("/")
def root():
    return {
        "platform": "VAJRA Cybersecurity & Threat Intelligence Platform",
        "status": "ONLINE",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/api/health"
    }

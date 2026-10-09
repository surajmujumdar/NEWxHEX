import os
from typing import List
from pydantic import BaseModel
from dotenv import load_dotenv
from pathlib import Path

# Load environment
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(env_path)

class HexStrikeSettings(BaseModel):
    ENABLED: bool = os.getenv("HEXSTRIKE_ENABLED", "true").lower() in ("true", "1", "yes", "on")
    URL: str = os.getenv("HEXSTRIKE_URL", os.getenv("HEXSTRIKE_BASE_URL", "http://localhost:8888")).rstrip("/")
    TIMEOUT: int = int(os.getenv("HEXSTRIKE_TIMEOUT", "300"))
    AUTO_FALLBACK: bool = os.getenv("HEXSTRIKE_AUTO_FALLBACK", "true").lower() in ("true", "1", "yes", "on")
    DEFAULT_PROFILE: str = os.getenv("HEXSTRIKE_DEFAULT_PROFILE", "STANDARD")
    MAX_CONCURRENT_TASKS: int = int(os.getenv("HEXSTRIKE_MAX_CONCURRENT_TASKS", "4"))
    
    # Tool Categories enabled
    ENABLED_CATEGORIES: List[str] = [
        "NETWORK",
        "WEB",
        "RECON",
        "OSINT",
        "CLOUD",
        "CONTAINER",
        "DNS",
        "TLS",
        "VULNERABILITY",
        "SCANNING",
        "SAST",
        "DAST",
        "SCA"
    ]

settings = HexStrikeSettings()

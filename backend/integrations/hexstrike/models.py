from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ToolCategory(str, Enum):
    NETWORK = "NETWORK"
    WEB = "WEB"
    RECON = "RECON"
    OSINT = "OSINT"
    CLOUD = "CLOUD"
    CONTAINER = "CONTAINER"
    DNS = "DNS"
    TLS = "TLS"
    VULNERABILITY = "VULNERABILITY"
    SCANNING = "SCANNING"
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanProfile(str, Enum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"

class ToolDefinition(BaseModel):
    name: str
    category: str
    capabilities: List[str] = Field(default_factory=list)
    hexstrike_supported: bool = True
    installed: bool = False
    version: Optional[str] = None
    description: Optional[str] = None
    binary_path: Optional[str] = None
    execution_type: str = "cli"  # cli, api, mcp
    last_checked: Optional[str] = None

    model_config = {"extra": "allow"}

class NormalizedFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"find-{uuid.uuid4().hex[:12]}")
    source: str = "hexstrike"  # hexstrike, sentinel, vajra
    tool: str = "unknown"
    category: str = "DAST"  # SAST, DAST, SCA, DOMAIN, SSL, NETWORK, RECON
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    target: str
    url: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_data: Optional[Dict[str, Any]] = None

    model_config = {"extra": "allow"}

class HexStrikeHealthStatus(BaseModel):
    status: str = "Disconnected"  # Connected, Disconnected, Partial
    reachable: bool = False
    api_available: bool = False
    mcp_available: bool = False
    tools_available: int = 0
    tools_unavailable: int = 0
    total_tools: int = 0
    latency_ms: Optional[float] = None
    version: Optional[str] = "v1.0-hexstrike"
    url: str = "http://localhost:8888"
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ScanExecutionSummary(BaseModel):
    scan_id: str
    project_id: Optional[str] = None
    target: str
    scan_type: str  # SAST, DAST, SCA, DOMAIN_PULSE, DOMAIN_ANALYSIS, SSL, COMBINED
    provider: str = "hexstrike"  # hexstrike, native_fallback, hybrid
    tools_used: List[str] = Field(default_factory=list)
    profile: str = "STANDARD"
    status: str = "COMPLETED"  # QUEUED, RUNNING, COMPLETED, FAILED, PARTIAL
    progress_percent: int = 100
    current_tool: Optional[str] = None
    current_stage: Optional[str] = None
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: List[NormalizedFinding] = Field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ToolSelectionRequest(BaseModel):
    target: str
    target_type: Optional[str] = "web"  # web, domain, ip, repo, source
    profile: Optional[ScanProfile] = ScanProfile.STANDARD
    category: Optional[str] = None
    scope: Optional[List[str]] = None

class ToolSelectionResponse(BaseModel):
    target: str
    profile: str
    selected_tools: List[str]
    rationale: Dict[str, str] = Field(default_factory=dict)
    source: str = "hexstrike_intelligence"  # hexstrike_intelligence or fallback_rules

class ParameterOptimizationRequest(BaseModel):
    tool: str
    target: str
    profile: Optional[ScanProfile] = ScanProfile.STANDARD
    custom_flags: Optional[Dict[str, Any]] = None

class ParameterOptimizationResponse(BaseModel):
    tool: str
    optimized_command: List[str]
    parameters: Dict[str, Any]
    reasoning: str

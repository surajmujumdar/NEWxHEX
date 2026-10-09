from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from .security_orchestrator import security_orchestrator
from .recon_orchestrator import domain_recon_orchestrator
from integrations.hexstrike.models import ScanExecutionSummary, ScanProfile

router = APIRouter(prefix="/orchestrator", tags=["Security Orchestrator"])

class StartScanRequest(BaseModel):
    target: str
    scan_type: str = "DAST"  # SAST, DAST, SCA, DOMAIN_PULSE, DOMAIN_ANALYSIS, SSL, COMBINED
    profile: Optional[ScanProfile] = ScanProfile.STANDARD
    project_id: Optional[str] = None
    custom_tools: Optional[List[str]] = None

@router.post("/scan", response_model=ScanExecutionSummary)
async def start_security_scan(payload: StartScanRequest):
    """
    Launch a centralized security scan across Sentinel or Vajra managed by SecurityOrchestrator.
    """
    try:
        summary = await security_orchestrator.scan(
            target=payload.target,
            scan_type=payload.scan_type,
            profile=payload.profile.value if payload.profile else "STANDARD",
            project_id=payload.project_id,
            custom_tools=payload.custom_tools
        )
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution error: {str(e)}")

@router.get("/scans", response_model=List[ScanExecutionSummary])
def list_scan_history(limit: int = Query(50, ge=1, le=200)):
    """
    Retrieve unified scan history across all security tools and engines.
    """
    return security_orchestrator.list_scans(limit=limit)

@router.get("/scans/{scan_id}", response_model=ScanExecutionSummary)
def get_scan_details(scan_id: str):
    """
    Get live status, progress, and normalized findings for an active or completed scan.
    """
    scan = security_orchestrator.get_scan_status(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan

@router.post("/domain-recon")
async def run_domain_recon(domain: str = Query(..., description="Target domain for pulse/recon analysis"), profile: str = Query("STANDARD")):
    """
    Execute HexStrike enhanced domain pulse reconnaissance.
    """
    try:
        return await domain_recon_orchestrator.analyze_domain(domain, profile=profile)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Domain recon error: {str(e)}")

@router.post("/domain-compare")
async def compare_domain_snapshots(payload: Dict[str, Any]):
    """
    Compare two domain snapshots for continuous drift monitoring.
    """
    prev_s = payload.get("previous_snapshot", {})
    curr_s = payload.get("current_snapshot", {})
    return await domain_recon_orchestrator.compare_domain_snapshots(prev_s, curr_s)

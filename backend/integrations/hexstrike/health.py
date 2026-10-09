from fastapi import APIRouter, Query, HTTPException, Depends
from typing import Optional, List, Dict, Any

from .client import hexstrike_client
from .tool_registry import tool_registry
from .adapter import hexstrike_adapter
from .models import (
    HexStrikeHealthStatus,
    ToolDefinition,
    ToolSelectionRequest,
    ToolSelectionResponse,
    ParameterOptimizationRequest,
    ParameterOptimizationResponse,
    NormalizedFinding
)

router = APIRouter(prefix="/integrations/hexstrike", tags=["HexStrike Integration"])

@router.get("/health", response_model=HexStrikeHealthStatus)
async def get_hexstrike_health():
    """
    Check the health of HexStrike AI security framework, MCP server, and local tool capabilities.
    Returns Connected, Disconnected, or Partial with tool counts and latencies.
    """
    try:
        status = await hexstrike_client.check_health()
        return status
    except Exception as e:
        summary = tool_registry.get_summary()
        return HexStrikeHealthStatus(
            status="Disconnected",
            reachable=False,
            api_available=False,
            mcp_available=False,
            tools_available=summary["available_tools"],
            tools_unavailable=summary["unavailable_tools"],
            total_tools=summary["total_tools"],
            error=str(e)
        )

@router.get("/tools", response_model=List[ToolDefinition])
def get_hexstrike_tools(
    category: Optional[str] = Query(None, description="Filter tools by category (e.g. WEB, NETWORK, RECON, SAST, SCA, TLS, DNS)"),
    installed_only: bool = Query(False, description="Only return tools with verified binaries installed")
):
    """
    Retrieve the normalized master registry of 150+ security tools with installation status and capabilities.
    """
    if category:
        tools = tool_registry.get_tools_by_category(category)
    else:
        tools = tool_registry.get_all_tools()

    if installed_only:
        tools = [t for t in tools if t.installed]

    return tools

@router.get("/summary")
def get_hexstrike_summary():
    """
    Get high-level summary of HexStrike security tools by category and availability.
    """
    return tool_registry.get_summary()

@router.post("/refresh-tools")
def refresh_tool_registry():
    """
    Trigger immediate re-scan of host PATH to detect newly installed security binaries.
    """
    tool_registry.refresh_availability()
    return {
        "status": "success",
        "message": "Tool registry refreshed successfully",
        "summary": tool_registry.get_summary()
    }

@router.post("/intelligence/select-tools", response_model=ToolSelectionResponse)
async def select_tools(payload: ToolSelectionRequest):
    """
    Intelligently select appropriate security tools for a target and profile.
    """
    res = await hexstrike_client.select_tools(
        target=payload.target,
        profile=payload.profile.value if payload.profile else "STANDARD",
        category=payload.category
    )
    return res

@router.post("/intelligence/analyze-target")
async def analyze_target(payload: Dict[str, Any]):
    """
    Analyze target attack surface and recommend penetration testing tools.
    """
    target = payload.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    target_type = payload.get("target_type", "web")
    return await hexstrike_client.analyze_target(target, target_type)

@router.post("/intelligence/optimize-parameters", response_model=ParameterOptimizationResponse)
async def optimize_parameters(payload: ParameterOptimizationRequest):
    """
    Get recommended CLI flags and parameters optimized for target and scan profile.
    """
    return await hexstrike_client.optimize_parameters(
        tool=payload.tool,
        target=payload.target,
        profile=payload.profile.value if payload.profile else "STANDARD"
    )

@router.post("/execute")
async def execute_tool_endpoint(payload: Dict[str, Any]):
    """
    Execute a security tool via the backend HexStrike adapter with failover and normalization.
    """
    tool = payload.get("tool")
    target = payload.get("target")
    if not tool or not target:
        raise HTTPException(status_code=400, detail="Both 'tool' and 'target' are required.")
    
    profile = payload.get("profile", "STANDARD")
    custom_flags = payload.get("custom_flags")
    
    result = await hexstrike_adapter.execute_tool(
        tool_name=tool,
        target=target,
        profile=profile,
        custom_flags=custom_flags
    )
    return result

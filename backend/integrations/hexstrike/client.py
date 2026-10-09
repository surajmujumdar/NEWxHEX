import httpx
import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .config import settings
from .models import (
    HexStrikeHealthStatus,
    ToolSelectionResponse,
    ParameterOptimizationResponse,
    ScanProfile
)
from .tool_registry import tool_registry

logger = logging.getLogger("hexstrike-client")

class HexStrikeClient:
    """
    Asynchronous client for HexStrike AI Security Framework API.
    Interacts with HexStrike Server or MCP bridge, with automatic fallback handling.
    """
    def __init__(self, base_url: Optional[str] = None, timeout: Optional[int] = None):
        self.base_url = (base_url or settings.URL).rstrip("/")
        self.timeout = timeout or settings.TIMEOUT
        self.enabled = settings.ENABLED

    async def check_health(self) -> HexStrikeHealthStatus:
        """
        Check health of HexStrike Server and local tool capability.
        Returns detailed status: 'Connected', 'Disconnected', or 'Partial'.
        """
        if not self.enabled:
            summary = tool_registry.get_summary()
            return HexStrikeHealthStatus(
                status="Disconnected",
                reachable=False,
                api_available=False,
                mcp_available=False,
                tools_available=summary["available_tools"],
                tools_unavailable=summary["unavailable_tools"],
                total_tools=summary["total_tools"],
                url=self.base_url,
                error="HexStrike integration is disabled via HEXSTRIKE_ENABLED=false."
            )

        start_time = time.time()
        reachable = False
        api_available = False
        mcp_available = False
        error_msg = None
        server_version = "v1.0-hexstrike"
        details: Dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                latency = round((time.time() - start_time) * 1000, 2)
                if resp.status_code == 200:
                    reachable = True
                    api_available = True
                    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                    server_version = data.get("version", server_version)
                    mcp_available = data.get("mcp_status", True)
                    details = data
                else:
                    error_msg = f"HTTP {resp.status_code} returned from {self.base_url}/health"
        except Exception as e:
            latency = round((time.time() - start_time) * 1000, 2)
            error_msg = f"Failed to connect to HexStrike at {self.base_url}: {str(e)}"
            logger.debug(f"[HexStrikeClient] Health check failed: {error_msg}")

        # Evaluate tool registry on local system
        summary = tool_registry.get_summary()
        available_tools = summary["available_tools"]
        unavailable_tools = summary["unavailable_tools"]
        total_tools = summary["total_tools"]

        if reachable and api_available:
            status = "Connected"
        elif available_tools > 0:
            status = "Partial"  # Local tools are installed and ready to execute via native fallback
        else:
            status = "Disconnected"

        return HexStrikeHealthStatus(
            status=status,
            reachable=reachable,
            api_available=api_available,
            mcp_available=mcp_available,
            tools_available=available_tools,
            tools_unavailable=unavailable_tools,
            total_tools=total_tools,
            latency_ms=latency if reachable else None,
            version=server_version,
            url=self.base_url,
            error=error_msg,
            details=details,
            checked_at=datetime.now(timezone.utc).isoformat()
        )

    async def execute_command(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute raw security command via HexStrike /api/command endpoint.
        """
        t = timeout or self.timeout
        try:
            async with httpx.AsyncClient(timeout=float(t)) as client:
                payload = {"command": command}
                resp = await client.post(f"{self.base_url}/api/command", json=payload)
                if resp.status_code == 200:
                    return resp.json()
                return {
                    "success": False,
                    "error": f"HexStrike server responded with HTTP {resp.status_code}: {resp.text}",
                    "stdout": "",
                    "stderr": resp.text
                }
        except Exception as e:
            logger.warning(f"[HexStrikeClient] Command execution failed over API: {e}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": str(e)
            }

    async def analyze_target(self, target: str, target_type: str = "web") -> Dict[str, Any]:
        """
        Analyze target attack surface using HexStrike intelligence or fallback heuristic.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                payload = {"target": target, "target_type": target_type}
                resp = await client.post(f"{self.base_url}/api/intelligence/analyze-target", json=payload)
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.debug(f"[HexStrikeClient] Intelligence analyze-target fallback: {e}")

        # Native Intelligent Heuristic Fallback
        is_url = target.startswith("http://") or target.startswith("https://")
        is_ip = target.replace(".", "").isdigit()
        
        target_category = "web" if is_url else ("network" if is_ip else "domain")
        recommended = []
        if target_category == "web":
            recommended = ["httpx", "nuclei", "wafw00f", "nikto", "dalfox"]
        elif target_category == "domain":
            recommended = ["subfinder", "dnsx", "amass", "httpx", "nuclei"]
        else:
            recommended = ["nmap", "rustscan", "nuclei"]

        return {
            "target": target,
            "target_type": target_category,
            "recommended_tools": recommended,
            "attack_surface": {
                "is_live_url": is_url,
                "protocol": "https" if "https://" in target else "http",
                "recommended_ports": [80, 443, 8080, 8443]
            },
            "source": "hexstrike_heuristic_engine"
        }

    async def select_tools(
        self,
        target: str,
        profile: str = "STANDARD",
        category: Optional[str] = None
    ) -> ToolSelectionResponse:
        """
        Select optimal security tools using HexStrike AI decision layer.
        Falls back to curated domain/DAST/SAST matrix if server is offline.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                payload = {
                    "target": target,
                    "profile": profile,
                    "category": category
                }
                resp = await client.post(f"{self.base_url}/api/intelligence/select-tools", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    tools_list = data.get("tools", [])
                    if tools_list:
                        return ToolSelectionResponse(
                            target=target,
                            profile=profile,
                            selected_tools=tools_list,
                            rationale=data.get("rationale", {}),
                            source="hexstrike_intelligence_server"
                        )
        except Exception as e:
            logger.debug(f"[HexStrikeClient] select-tools fallback: {e}")

        # Intelligent Fallback Selection Engine based on Profile & Category
        prof = profile.upper()
        selected: List[str] = []
        rationale: Dict[str, str] = {}

        if category == "SAST":
            if prof == "QUICK":
                selected = ["semgrep", "gitleaks"]
            elif prof == "DEEP":
                selected = ["semgrep", "bandit", "gitleaks", "trufflehog", "flawfinder"]
            else:  # STANDARD
                selected = ["semgrep", "bandit", "gitleaks"]
            rationale = {t: f"Selected for {prof} static code analysis." for t in selected}

        elif category == "SCA":
            if prof == "QUICK":
                selected = ["osv-scanner", "pip-audit"]
            elif prof == "DEEP":
                selected = ["trivy", "osv-scanner", "pip-audit", "npm-audit", "grype"]
            else:
                selected = ["osv-scanner", "pip-audit", "trivy"]
            rationale = {t: f"Selected for {prof} dependency audit." for t in selected}

        elif category in ("DOMAIN", "DOMAIN_PULSE", "RECON"):
            if prof == "QUICK":
                selected = ["dnsx", "subfinder", "httpx"]
            elif prof == "DEEP":
                selected = ["subfinder", "amass", "assetfinder", "dnsx", "massdns", "httpx", "nmap", "testssl"]
            else:
                selected = ["subfinder", "dnsx", "httpx", "amass", "nmap"]
            rationale = {t: f"Selected for {prof} domain reconnaissance." for t in selected}

        elif category == "SSL":
            if prof == "QUICK":
                selected = ["sslscan"]
            elif prof == "DEEP":
                selected = ["testssl", "sslscan", "sslyze"]
            else:
                selected = ["testssl", "sslscan"]
            rationale = {t: f"Selected for {prof} SSL/TLS certificate audit." for t in selected}

        else:  # DAST / WEB (Default)
            if prof == "QUICK":
                selected = ["httpx", "nuclei", "wafw00f"]
            elif prof == "DEEP":
                selected = ["httpx", "wafw00f", "nuclei", "nikto", "dalfox", "gobuster", "ffuf", "sqlmap", "nmap"]
            else:  # STANDARD
                selected = ["httpx", "wafw00f", "nuclei", "nikto", "dalfox"]
            rationale = {t: f"Selected for {prof} dynamic security scanning." for t in selected}

        # Filter against available installed tools if auto-fallback is enabled
        available_names = {t.name for t in tool_registry.get_available_tools()}
        if available_names:
            # Prefer installed tools, but keep list informative
            final_tools = [t for t in selected if t in available_names]
            if not final_tools:
                # If none of selected are installed, fallback to primary default tools
                final_tools = selected[:2]
        else:
            final_tools = selected

        return ToolSelectionResponse(
            target=target,
            profile=prof,
            selected_tools=final_tools,
            rationale=rationale,
            source="hexstrike_expert_rules"
        )

    async def optimize_parameters(
        self,
        tool: str,
        target: str,
        profile: str = "STANDARD"
    ) -> ParameterOptimizationResponse:
        """
        Get parameter optimization recommendations from HexStrike AI.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                payload = {"tool": tool, "target": target, "profile": profile}
                resp = await client.post(f"{self.base_url}/api/intelligence/optimize-parameters", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    return ParameterOptimizationResponse(
                        tool=tool,
                        optimized_command=data.get("command", []),
                        parameters=data.get("parameters", {}),
                        reasoning=data.get("reasoning", "Optimized by HexStrike AI")
                    )
        except Exception as e:
            logger.debug(f"[HexStrikeClient] optimize-parameters fallback: {e}")

        # Built-in profile-based parameter optimizer
        prof = profile.upper()
        cmd: List[str] = [tool]
        params: Dict[str, Any] = {}
        reasoning = f"Applied standard parameters for {prof} profile on target {target}"

        if tool == "nuclei":
            if prof == "QUICK":
                cmd = ["nuclei", "-u", target, "-severity", "critical,high", "-silent", "-jsonl"]
            elif prof == "DEEP":
                cmd = ["nuclei", "-u", target, "-silent", "-jsonl", "-c", "50", "-retries", "2"]
            else:
                cmd = ["nuclei", "-u", target, "-severity", "critical,high,medium", "-silent", "-jsonl"]

        elif tool == "httpx":
            cmd = ["httpx", "-u", target, "-silent", "-title", "-tech-detect", "-status-code", "-json"]

        elif tool == "nmap":
            if prof == "QUICK":
                cmd = ["nmap", "-T4", "-F", target]
            elif prof == "DEEP":
                cmd = ["nmap", "-T3", "-sV", "-sC", "-p-", target]
            else:
                cmd = ["nmap", "-T4", "-sV", "--top-ports", "100", target]

        elif tool == "nikto":
            cmd = ["nikto", "-h", target, "-Format", "json", "-Tuning", "1,2,3,4,8"]

        elif tool == "subfinder":
            cmd = ["subfinder", "-d", target, "-silent"]

        elif tool == "semgrep":
            cmd = ["semgrep", "scan", "--config", "auto", "--json", target]

        elif tool == "gitleaks":
            cmd = ["gitleaks", "detect", "--source", target, "--report-format", "json"]

        elif tool == "osv-scanner":
            cmd = ["osv-scanner", "--format", "json", "-r", target]

        elif tool == "testssl":
            cmd = ["testssl.sh", "--json", target]

        return ParameterOptimizationResponse(
            tool=tool,
            optimized_command=cmd,
            parameters=params,
            reasoning=reasoning
        )

# Global Client Instance
hexstrike_client = HexStrikeClient()

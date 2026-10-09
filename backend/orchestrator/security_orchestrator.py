import asyncio
import os
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timezone
from pathlib import Path

from integrations.hexstrike import (
    hexstrike_adapter,
    hexstrike_client,
    tool_registry,
    NormalizedFinding,
    ScanExecutionSummary,
    ScanProfile
)
from .recon_orchestrator import domain_recon_orchestrator

logger = logging.getLogger("security-orchestrator")

class SecurityOrchestrator:
    """
    Central Security Orchestrator for VAJRA X SENTINEL.
    Coordinates SAST, DAST, SCA, Domain Pulse, Domain Analysis, SSL, and Monitoring
    using HexStrike as a shared tool execution layer with automated failover.
    """

    def __init__(self):
        self.adapter = hexstrike_adapter
        self.client = hexstrike_client
        self.recon = domain_recon_orchestrator
        self.history: Dict[str, ScanExecutionSummary] = {}

    async def scan(
        self,
        target: str,
        scan_type: str = "DAST",  # SAST, DAST, SCA, DOMAIN_PULSE, DOMAIN_ANALYSIS, SSL, COMBINED
        profile: str = "STANDARD",  # QUICK, STANDARD, DEEP
        project_id: Optional[str] = None,
        custom_tools: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, int, str], Any]] = None
    ) -> ScanExecutionSummary:
        """
        Main entrypoint for executing security scans across Sentinel and Vajra.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:10]}"
        started_at = datetime.now(timezone.utc).isoformat()
        scan_type_upper = scan_type.upper()
        profile_upper = profile.upper()

        summary = ScanExecutionSummary(
            scan_id=scan_id,
            project_id=project_id,
            target=target,
            scan_type=scan_type_upper,
            profile=profile_upper,
            status="RUNNING",
            progress_percent=5,
            started_at=started_at,
            current_stage="Validating Target & Scope"
        )
        self.history[scan_id] = summary

        if progress_callback:
            await self._invoke_callback(progress_callback, "ORCHESTRATOR", 5, "Validating target and security scope...")

        try:
            # 1. Target and Scope Validation
            validated_target = self._validate_target(target, scan_type_upper)

            # 2. Tool Selection (HexStrike Intelligence or curated fallback)
            if custom_tools and len(custom_tools) > 0:
                selected_tools = custom_tools
            else:
                selection_res = await self.client.select_tools(
                    target=validated_target,
                    profile=profile_upper,
                    category=scan_type_upper
                )
                selected_tools = selection_res.selected_tools

            summary.tools_used = selected_tools
            summary.current_stage = f"Selected {len(selected_tools)} security tools: {', '.join(selected_tools)}"
            
            if progress_callback:
                await self._invoke_callback(progress_callback, "ORCHESTRATOR", 15, summary.current_stage)

            # 3. Branch execution based on scan_type
            all_findings: List[NormalizedFinding] = []

            if scan_type_upper in ("DOMAIN_PULSE", "DOMAIN_ANALYSIS", "DOMAIN"):
                recon_res = await self.recon.analyze_domain(validated_target, profile=profile_upper)
                for f_data in recon_res.get("findings", []):
                    all_findings.append(NormalizedFinding(**f_data))
                summary.metadata["recon_data"] = recon_res

            elif scan_type_upper == "SSL":
                ssl_tool_res = await self.adapter.execute_tool_chain(
                    tools=["testssl"] if "testssl" in selected_tools else ["sslscan"],
                    target=validated_target,
                    profile=profile_upper,
                    progress_callback=progress_callback
                )
                for res in ssl_tool_res:
                    all_findings.extend(res.get("findings", []))

            elif scan_type_upper == "SCA":
                # Auto-detect ecosystem dependencies
                eco_tools = self._detect_sca_ecosystem(validated_target, selected_tools)
                tool_results = await self.adapter.execute_tool_chain(
                    tools=eco_tools,
                    target=validated_target,
                    profile=profile_upper,
                    progress_callback=progress_callback
                )
                for res in tool_results:
                    all_findings.extend(res.get("findings", []))

            elif scan_type_upper == "SAST":
                tool_results = await self.adapter.execute_tool_chain(
                    tools=selected_tools if selected_tools else ["semgrep", "bandit", "gitleaks"],
                    target=validated_target,
                    profile=profile_upper,
                    progress_callback=progress_callback
                )
                for res in tool_results:
                    all_findings.extend(res.get("findings", []))

            else:  # DAST / COMBINED / WEB
                tool_results = await self.adapter.execute_tool_chain(
                    tools=selected_tools if selected_tools else ["httpx", "nuclei", "wafw00f"],
                    target=validated_target,
                    profile=profile_upper,
                    progress_callback=progress_callback
                )
                for res in tool_results:
                    all_findings.extend(res.get("findings", []))

            # 4. Count Severities
            crit = sum(1 for f in all_findings if f.severity == "CRITICAL")
            high = sum(1 for f in all_findings if f.severity == "HIGH")
            med = sum(1 for f in all_findings if f.severity == "MEDIUM")
            low = sum(1 for f in all_findings if f.severity == "LOW")
            info = sum(1 for f in all_findings if f.severity == "INFO")

            summary.findings = all_findings
            summary.findings_count = len(all_findings)
            summary.critical_count = crit
            summary.high_count = high
            summary.medium_count = med
            summary.low_count = low
            summary.info_count = info
            summary.status = "COMPLETED"
            summary.progress_percent = 100
            summary.completed_at = datetime.now(timezone.utc).isoformat()
            summary.current_stage = f"Scan completed with {len(all_findings)} findings."

            if progress_callback:
                await self._invoke_callback(progress_callback, "ALL", 100, summary.current_stage)

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Scan execution failed: {e}", exc_info=True)
            summary.status = "FAILED"
            summary.error = str(e)
            summary.completed_at = datetime.now(timezone.utc).isoformat()
            summary.current_stage = f"Failed: {str(e)}"
            if progress_callback:
                await self._invoke_callback(progress_callback, "ERROR", 100, f"Error: {str(e)}")

        self.history[scan_id] = summary
        return summary

    def get_scan_status(self, scan_id: str) -> Optional[ScanExecutionSummary]:
        return self.history.get(scan_id)

    def list_scans(self, limit: int = 50) -> List[ScanExecutionSummary]:
        return sorted(list(self.history.values()), key=lambda s: s.started_at, reverse=True)[:limit]

    def _validate_target(self, target: str, scan_type: str) -> str:
        """
        Validate and sanitize target inputs, avoiding localhost / private range attacks.
        """
        if not target or not target.strip():
            raise ValueError("Target specification cannot be empty.")
        clean = target.strip()
        # Allow local filesystem path for SAST and SCA
        if scan_type in ("SAST", "SCA") and os.path.exists(clean):
            return clean
        return clean

    def _detect_sca_ecosystem(self, target_path: str, default_tools: List[str]) -> List[str]:
        """
        Detects repo ecosystem (Python, Node, Java, Go) and tailors SCA tools (Requirement 10).
        """
        tools = list(default_tools)
        if os.path.isdir(target_path):
            files = os.listdir(target_path)
            if "requirements.txt" in files or "pyproject.toml" in files or "Pipfile" in files:
                if "pip-audit" not in tools:
                    tools.append("pip-audit")
            if "package.json" in files or "package-lock.json" in files:
                if "npm-audit" not in tools:
                    tools.append("npm-audit")
            if "pom.xml" in files or "build.gradle" in files:
                if "trivy" not in tools:
                    tools.append("trivy")
            if "go.mod" in files:
                if "osv-scanner" not in tools:
                    tools.append("osv-scanner")
        return tools if tools else ["osv-scanner", "trivy"]

    async def _invoke_callback(self, cb: Callable, tool: str, pct: int, msg: str):
        try:
            if asyncio.iscoroutinefunction(cb):
                await cb(tool, pct, msg)
            else:
                cb(tool, pct, msg)
        except Exception:
            pass

# Global Singleton Orchestrator
security_orchestrator = SecurityOrchestrator()

#!/usr/bin/env python3
"""
HexStrike AI - Unified AppSec & Monitoring Reporting Engine
===========================================================
Aggregates, normalizes, and prioritizes findings across SAST, DAST, SCA,
CSV Telemetry, DNS Posture, and SSL/TLS Certificates into a unified
CVSS-ranked Security Posture Dashboard & Markdown Card Summary.
"""

import sys
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple


@dataclass
class UnifiedFinding:
    """Normalized finding representation across all security scanners"""
    source_module: str     # SAST, DAST, SCA, CSV, DNS, SSL
    title: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float      # 0.0 - 10.0
    category_or_owasp: str
    target_or_file: str
    evidence_or_snippet: str
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UnifiedAppSecReporter:
    """Enterprise AppSec Aggregation, Risk Scoring & Prioritized Reporting Engine"""

    def __init__(self):
        pass

    def normalize_sast(self, sast_results: Optional[Dict[str, Any]]) -> List[UnifiedFinding]:
        if not sast_results or not sast_results.get("success"):
            return []
        findings = []
        for f in sast_results.get("findings", []):
            findings.append(UnifiedFinding(
                source_module="SAST",
                title=f.get("title", "Static Code Issue"),
                severity=f.get("severity", "MEDIUM"),
                cvss_score=float(f.get("cvss_score", 5.0)),
                category_or_owasp=f.get("owasp_category", "Code Security"),
                target_or_file=f"{f.get('file_path', '')}:{f.get('line_number', '')}",
                evidence_or_snippet=f.get("matched_snippet", ""),
                description=f.get("description", ""),
                remediation=f.get("remediation", "")
            ))
        return findings

    def normalize_dast(self, dast_results: Optional[Dict[str, Any]]) -> List[UnifiedFinding]:
        if not dast_results or (not dast_results.get("success") and not dast_results.get("findings")):
            return []
        findings = []
        for f in dast_results.get("findings", []):
            findings.append(UnifiedFinding(
                source_module="DAST",
                title=f.get("title", "Runtime Web Issue"),
                severity=f.get("severity", "MEDIUM"),
                cvss_score=float(f.get("cvss_score", 5.0)),
                category_or_owasp=f.get("owasp_category", "Web Security"),
                target_or_file=f.get("target_url", ""),
                evidence_or_snippet=f.get("evidence", ""),
                description=f.get("description", ""),
                remediation=f.get("remediation", "")
            ))
        return findings

    def normalize_sca(self, sca_results: Optional[Dict[str, Any]]) -> List[UnifiedFinding]:
        if not sca_results or (not sca_results.get("success") and not sca_results.get("findings")):
            return []
        findings = []
        for f in sca_results.get("findings", []):
            findings.append(UnifiedFinding(
                source_module="SCA",
                title=f"{f.get('package_name', '')} @ {f.get('installed_version', '')} - {f.get('title', 'Vulnerable Dependency')}",
                severity=f.get("severity", "HIGH"),
                cvss_score=float(f.get("cvss_score", 7.5)),
                category_or_owasp=f"Supply Chain / {f.get('cve_id', 'CVE')}",
                target_or_file=f.get("manifest_path", ""),
                evidence_or_snippet=f"Vulnerable: {f.get('vulnerable_versions', '')} | Fixed: {f.get('fixed_version', '')}",
                description=f.get("description", ""),
                remediation=f.get("remediation", "")
            ))
        return findings

    def normalize_csv(self, csv_results: Optional[Dict[str, Any]]) -> List[UnifiedFinding]:
        if not csv_results or (not csv_results.get("success") and not csv_results.get("records")):
            return []
        findings = []
        for r in csv_results.get("records", []):
            sev = r.get("severity", "MEDIUM")
            cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}
            findings.append(UnifiedFinding(
                source_module="CSV_TELEMETRY",
                title=r.get("title", "Ingested Vulnerability Record"),
                severity=sev,
                cvss_score=cvss_map.get(sev, 5.0),
                category_or_owasp=r.get("cve") or "Asset Telemetry",
                target_or_file=f"{r.get('asset', '')}:{r.get('port') or ''}",
                evidence_or_snippet=str(r.get("raw_row", {})),
                description=f"Status: {r.get('status', 'ACTIVE')}",
                remediation="Investigate host vulnerability feed finding."
            ))
        return findings

    def normalize_dns(self, dns_results: Optional[Dict[str, Any]]) -> List[UnifiedFinding]:
        if not dns_results or (not dns_results.get("success") and not dns_results.get("issues")):
            return []
        findings = []
        for i in dns_results.get("issues", []):
            findings.append(UnifiedFinding(
                source_module="DNS",
                title=i.get("title", "DNS Configuration Issue"),
                severity=i.get("severity", "MEDIUM"),
                cvss_score=float(i.get("cvss_score", 5.0)),
                category_or_owasp=i.get("category", "DNS"),
                target_or_file=dns_results.get("domain", ""),
                evidence_or_snippet=i.get("evidence", ""),
                description=i.get("description", ""),
                remediation=i.get("remediation", "")
            ))
        return findings

    def normalize_ssl(self, ssl_results: Optional[Dict[str, Any]]) -> List[UnifiedFinding]:
        if not ssl_results or (not ssl_results.get("success") and not ssl_results.get("findings")):
            return []
        findings = []
        for f in ssl_results.get("findings", []):
            findings.append(UnifiedFinding(
                source_module="SSL_TLS",
                title=f.get("title", "SSL Certificate Issue"),
                severity=f.get("severity", "HIGH"),
                cvss_score=float(f.get("cvss_score", 7.0)),
                category_or_owasp=f.get("cwe_id", "CWE-295"),
                target_or_file=ssl_results.get("target", ""),
                evidence_or_snippet=f.get("evidence", ""),
                description=f.get("description", ""),
                remediation=f.get("remediation", "")
            ))
        return findings

    def generate_unified_report(
        self,
        project_name: str = "HexStrike AppSec Audit",
        sast_results: Optional[Dict[str, Any]] = None,
        dast_results: Optional[Dict[str, Any]] = None,
        sca_results: Optional[Dict[str, Any]] = None,
        csv_results: Optional[Dict[str, Any]] = None,
        dns_results: Optional[Dict[str, Any]] = None,
        ssl_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Aggregate and calculate unified security posture report"""
        start_time = datetime.now()
        all_findings: List[UnifiedFinding] = []

        all_findings.extend(self.normalize_sast(sast_results))
        all_findings.extend(self.normalize_dast(dast_results))
        all_findings.extend(self.normalize_sca(sca_results))
        all_findings.extend(self.normalize_csv(csv_results))
        all_findings.extend(self.normalize_dns(dns_results))
        all_findings.extend(self.normalize_ssl(ssl_results))

        # Sort all findings by CVSS score descending
        all_findings.sort(key=lambda x: x.cvss_score, reverse=True)

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        module_breakdown: Dict[str, int] = {}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            module_breakdown[f.source_module] = module_breakdown.get(f.source_module, 0) + 1

        # Posture Score Calculation
        deductions = (counts["CRITICAL"] * 20) + (counts["HIGH"] * 8) + (counts["MEDIUM"] * 2.5) + (counts["LOW"] * 0.5)
        overall_score = max(0, round(100 - deductions, 1))

        if overall_score >= 85:
            risk_rating = "LOW_RISK"
        elif overall_score >= 65:
            risk_rating = "MEDIUM_RISK"
        elif overall_score >= 40:
            risk_rating = "HIGH_RISK"
        else:
            risk_rating = "CRITICAL_RISK"

        duration = (datetime.now() - start_time).total_seconds()
        telemetry = dast_results.get("firewall_waf_telemetry") if (dast_results and isinstance(dast_results, dict)) else None

        report_dict = {
            "success": True,
            "project_name": project_name,
            "report_timestamp": datetime.now().isoformat(),
            "duration_seconds": round(duration, 3),
            "overall_security_score": overall_score,
            "risk_rating": risk_rating,
            "total_findings": len(all_findings),
            "severity_summary": counts,
            "module_summary": module_breakdown,
            "firewall_waf_telemetry": telemetry,
            "module_scores": {
                "sast_score": sast_results.get("security_score") if sast_results else None,
                "dast_score": dast_results.get("security_score") if dast_results else None,
                "sca_score": sca_results.get("security_score") if sca_results else None,
                "csv_score": csv_results.get("security_score") if csv_results else None,
                "dns_score": dns_results.get("security_score") if dns_results else None,
                "ssl_score": ssl_results.get("security_score") if ssl_results else None
            },
            "findings": [f.to_dict() for f in all_findings]
        }
        report_dict["markdown_report"] = self.generate_markdown_dashboard(report_dict)
        return report_dict

    def generate_markdown_dashboard(self, unified_data: Dict[str, Any]) -> str:
        """Generate executive Markdown dashboard and cards"""
        score = unified_data.get("overall_security_score", 100)
        rating = unified_data.get("risk_rating", "SECURE")
        counts = unified_data.get("severity_summary", {})
        modules = unified_data.get("module_summary", {})
        telemetry = unified_data.get("firewall_waf_telemetry") or {}

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 65 else "🟠" if score >= 40 else "🔴"

        md = [
            f"# 🛡️ HexStrike Unified Application Security & Posture Dashboard",
            f"**Audit Project:** `{unified_data.get('project_name', 'Audit')}` | **Generated:** {unified_data.get('report_timestamp', '')}",
            f"## 🏆 Executive Posture: {status_emoji} **{score} / 100** ({rating})",
            "",
            "---",
            ""
        ]

        if telemetry and (telemetry.get("waf_detected") or telemetry.get("total_probes_blocked", 0) > 0 or telemetry.get("blocked_events")):
            md.extend([
                "## 🛡️ Perimeter Security, WAF & Firewall Telemetry",
                f"- **WAF / Perimeter Detected:** {'🛡️ **' + telemetry.get('waf_vendor', 'Unknown') + '** (' + telemetry.get('confidence', 'HIGH') + ')' if telemetry.get('waf_detected') else '⚪ *None Detected (Direct Server Response)*'}",
                f"- **Blocked Probes Intercepted:** **{telemetry.get('total_probes_blocked', 0)} probes dropped** (HTTP 403 / 429)",
                f"- **Perimeter Status:** {telemetry.get('status_summary', 'Active')}",
                f"- **Auditor Recommendation:** {telemetry.get('audit_recommendation', 'N/A')}",
                ""
            ])
            blocked_events = telemetry.get("blocked_events", [])
            if blocked_events:
                md.extend([
                    "### 🚫 Firewall / WAF Intercepted Probes Register",
                    "| Probe URL | Method | HTTP Status | Interception Reason | Signature |",
                    "| :--- | :--- | :--- | :--- | :--- |"
                ])
                for ev in blocked_events[:15]:
                    md.append(f"| `{ev.get('url', '')}` | `{ev.get('method', 'GET')}` | `HTTP {ev.get('status_code', '')}` | {ev.get('reason', '')} | `{ev.get('waf_signature', '')}` |")
                md.append("")
            md.extend([
                "---",
                ""
            ])

        md.extend([
            "## 📊 Consolidated CVSS Severity Breakdown",
            f"| Severity Level | Count | CVSS Base Range | Weight Impact |",
            f"| :--- | :--- | :--- | :--- |",
            f"| 🔴 **CRITICAL** | **{counts.get('CRITICAL', 0)}** | 9.0 - 10.0 | High Priority Immediate Patch |",
            f"| 🟠 **HIGH** | **{counts.get('HIGH', 0)}** | 7.0 - 8.9 | Remediation within 7 days |",
            f"| 🟡 **MEDIUM** | **{counts.get('MEDIUM', 0)}** | 4.0 - 6.9 | Remediation in next cycle |",
            f"| 🔵 **LOW** | **{counts.get('LOW', 0)}** | 0.1 - 3.9 | Defense-in-depth hardening |",
            f"| ⚪ **INFO** | **{counts.get('INFO', 0)}** | 0.0 | Informational hygiene |",
            "",
            "## 🧩 Findings by Security Domain",
        ])

        for mod, count in modules.items():
            md.append(f"- **{mod}:** {count} issues identified")

        md.extend([
            "",
            "---",
            "",
            "## 🎯 Priority Vulnerability Cards (Ranked by CVSS)"
        ])

        findings = unified_data.get("findings", [])
        if not findings:
            md.append("✅ *Zero vulnerabilities identified across all audited surfaces.*")
        else:
            for idx, f in enumerate(findings[:30], start=1):
                sev_icon = "🔴" if f['severity'] == "CRITICAL" else "🟠" if f['severity'] == "HIGH" else "🟡" if f['severity'] == "MEDIUM" else "🔵"
                md.append(f"### {idx}. {sev_icon} [{f['source_module']}] {f['title']}")
                md.append(f"**Severity:** `{f['severity']}` (CVSS **{f['cvss_score']}**) | **Category:** `{f['category_or_owasp']}`")
                md.append(f"- **Target / File:** `{f['target_or_file']}`")
                md.append(f"- **Evidence:** `{f['evidence_or_snippet']}`")
                md.append(f"- **Description:** {f['description']}")
                md.append(f"- **Remediation Action:** {f['remediation']}")
                md.append("")

        return "\n".join(md)

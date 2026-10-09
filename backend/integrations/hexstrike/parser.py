import json
import re
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .models import NormalizedFinding, SeverityLevel

class OutputParser:
    """
    Normalizes diverse scanner outputs into standardized NormalizedFinding records
    compatible with Sentinel Finding models and Vajra Alert entities.
    """

    @classmethod
    def parse(cls, tool_name: str, raw_output: str, target: str, category: str = "DAST") -> List[NormalizedFinding]:
        if not raw_output or not raw_output.strip():
            return []

        tool = tool_name.lower()
        findings: List[NormalizedFinding] = []

        try:
            if tool == "nuclei":
                findings = cls._parse_nuclei(raw_output, target)
            elif tool == "nikto":
                findings = cls._parse_nikto(raw_output, target)
            elif tool == "nmap":
                findings = cls._parse_nmap(raw_output, target)
            elif tool == "httpx":
                findings = cls._parse_httpx(raw_output, target)
            elif tool == "semgrep":
                findings = cls._parse_semgrep(raw_output, target)
            elif tool == "bandit":
                findings = cls._parse_bandit(raw_output, target)
            elif tool == "gitleaks":
                findings = cls._parse_gitleaks(raw_output, target)
            elif tool in ("osv-scanner", "osv"):
                findings = cls._parse_osv(raw_output, target)
            elif tool == "trivy":
                findings = cls._parse_trivy(raw_output, target)
            elif tool in ("pip-audit", "npm-audit"):
                findings = cls._parse_audit(raw_output, target, tool)
            elif tool in ("testssl", "sslscan", "sslyze"):
                findings = cls._parse_ssl(raw_output, target, tool)
            elif tool in ("subfinder", "amass", "assetfinder", "dnsx"):
                findings = cls._parse_recon(raw_output, target, tool)
            elif tool == "wafw00f":
                findings = cls._parse_wafw00f(raw_output, target)
            else:
                findings = cls._parse_generic(raw_output, target, tool, category)
        except Exception as e:
            # Fallback to generic parsing on any formatting error
            findings = cls._parse_generic(raw_output, target, tool, category, error=str(e))

        return findings

    @classmethod
    def _parse_nuclei(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev_raw = info.get("severity", "info").upper()
                sev = sev_raw if sev_raw in SeverityLevel._member_names_ else "INFO"

                cve_id = None
                cve_list = info.get("classification", {}).get("cve-id", [])
                if cve_list:
                    cve_id = cve_list[0] if isinstance(cve_list, list) else str(cve_list)

                cwe_id = None
                cwe_list = info.get("classification", {}).get("cwe-id", [])
                if cwe_list:
                    cwe_id = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)

                cvss_score = info.get("classification", {}).get("cvss-score")
                
                finding = NormalizedFinding(
                    source="hexstrike",
                    tool="nuclei",
                    category="DAST",
                    severity=sev,
                    title=info.get("name") or data.get("template-id") or "Nuclei Security Finding",
                    description=info.get("description") or f"Detected vulnerability via Nuclei template {data.get('template-id')}",
                    target=target,
                    url=data.get("matched-at") or data.get("host") or target,
                    cve=cve_id,
                    cwe=cwe_id,
                    cvss_score=float(cvss_score) if cvss_score else None,
                    evidence=data.get("extracted-results", [data.get("matcher-name")])[0] if data.get("extracted-results") else data.get("matcher-name"),
                    recommendation=info.get("remediation") or "Patch affected component or update configuration to latest secure baseline.",
                    raw_data=data
                )
                findings.append(finding)
            except Exception:
                # Text line fallback
                if "[" in line and "]" in line:
                    parts = line.split()
                    findings.append(NormalizedFinding(
                        source="hexstrike",
                        tool="nuclei",
                        category="DAST",
                        severity="INFO",
                        title=f"Nuclei Finding: {line[:50]}",
                        description=line,
                        target=target,
                        url=target
                    ))
        return findings

    @classmethod
    def _parse_nikto(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            items = data.get("vulnerabilities", []) or data.get("items", [])
            for item in items:
                msg = item.get("msg") or item.get("description") or "Nikto Finding"
                findings.append(NormalizedFinding(
                    source="hexstrike",
                    tool="nikto",
                    category="DAST",
                    severity="LOW",
                    title=f"Web Misconfiguration: {msg[:60]}",
                    description=msg,
                    target=target,
                    url=item.get("url") or target,
                    cve=item.get("id"),
                    recommendation="Review web server headers and configuration according to CIS benchmarks.",
                    raw_data=item
                ))
        except Exception:
            for line in output.splitlines():
                if line.startswith("+ "):
                    text = line[2:].strip()
                    findings.append(NormalizedFinding(
                        source="hexstrike",
                        tool="nikto",
                        category="DAST",
                        severity="LOW",
                        title=f"Nikto Warning: {text[:60]}",
                        description=text,
                        target=target,
                        url=target,
                        recommendation="Harden web server configuration."
                    ))
        return findings

    @classmethod
    def _parse_nmap(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        open_ports = []
        for line in output.splitlines():
            m = re.match(r"^(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                port_proto, service, version = m.groups()
                open_ports.append(f"{port_proto} ({service} {version})".strip())
                findings.append(NormalizedFinding(
                    source="hexstrike",
                    tool="nmap",
                    category="NETWORK",
                    severity="INFO" if int(port_proto.split("/")[0]) in (80, 443) else "LOW",
                    title=f"Open Port Discovered: {port_proto} ({service})",
                    description=f"Port {port_proto} is publicly accessible running service {service} {version}".strip(),
                    target=target,
                    recommendation="Verify if this port is intended for public exposure. Restrict access via security groups/firewall if unnecessary."
                ))
        return findings

    @classmethod
    def _parse_httpx(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        for line in output.strip().splitlines():
            try:
                data = json.loads(line)
                title = data.get("title", "")
                tech = data.get("tech", [])
                status_code = data.get("status_code")
                url = data.get("url") or target

                desc = f"HTTP Endpoint {url} responded with status {status_code}."
                if tech:
                    desc += f" Technologies detected: {', '.join(tech)}."
                if title:
                    desc += f" Page title: '{title}'."

                findings.append(NormalizedFinding(
                    source="hexstrike",
                    tool="httpx",
                    category="RECON",
                    severity="INFO",
                    title=f"HTTP Service Fingerprint ({status_code})",
                    description=desc,
                    target=target,
                    url=url,
                    evidence=f"Technologies: {tech}",
                    raw_data=data
                ))
            except Exception:
                if line.strip():
                    findings.append(NormalizedFinding(
                        source="hexstrike",
                        tool="httpx",
                        category="RECON",
                        severity="INFO",
                        title=f"Live Endpoint Probed: {line[:50]}",
                        description=line,
                        target=target,
                        url=target
                    ))
        return findings

    @classmethod
    def _parse_semgrep(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            for res in data.get("results", []):
                extra = res.get("extra", {})
                sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                sev = sev_map.get(extra.get("severity", "").upper(), "MEDIUM")

                findings.append(NormalizedFinding(
                    source="hexstrike",
                    tool="semgrep",
                    category="SAST",
                    severity=sev,
                    title=extra.get("message", "Semgrep Security Finding").split("\n")[0][:80],
                    description=extra.get("message", "Static security finding"),
                    target=target,
                    file_path=res.get("path"),
                    line_number=res.get("start", {}).get("line"),
                    cwe=extra.get("metadata", {}).get("cwe", [None])[0] if isinstance(extra.get("metadata", {}).get("cwe"), list) else None,
                    recommendation=extra.get("fix") or "Refactor code to prevent unsafe pattern.",
                    evidence=extra.get("lines"),
                    raw_data=res
                ))
        except Exception:
            pass
        return findings

    @classmethod
    def _parse_bandit(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            for res in data.get("results", []):
                findings.append(NormalizedFinding(
                    source="hexstrike",
                    tool="bandit",
                    category="SAST",
                    severity=res.get("issue_severity", "MEDIUM").upper(),
                    title=res.get("issue_text", "Python Security Issue"),
                    description=f"{res.get('issue_text')} in {res.get('filename')}:{res.get('line_number')}",
                    target=target,
                    file_path=res.get("filename"),
                    line_number=res.get("line_number"),
                    cwe=res.get("issue_cwe", {}).get("id") if isinstance(res.get("issue_cwe"), dict) else None,
                    evidence=res.get("code"),
                    recommendation="Review and remediate Python security vulnerability.",
                    raw_data=res
                ))
        except Exception:
            pass
        return findings

    @classmethod
    def _parse_gitleaks(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            items = data if isinstance(data, list) else [data]
            for item in items:
                rule = item.get("RuleID") or item.get("Description") or "Hardcoded Secret"
                findings.append(NormalizedFinding(
                    source="hexstrike",
                    tool="gitleaks",
                    category="SAST",
                    severity="HIGH",
                    title=f"Secret Exposed: {rule}",
                    description=f"Potential credential/token exposed in {item.get('File')}:{item.get('StartLine')}",
                    target=target,
                    file_path=item.get("File"),
                    line_number=item.get("StartLine"),
                    evidence=item.get("Match", "")[:30] + "...",
                    recommendation="Revoke and rotate exposed credentials immediately, then purge commit history.",
                    raw_data=item
                ))
        except Exception:
            pass
        return findings

    @classmethod
    def _parse_osv(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            for res in data.get("results", []):
                for pkg in res.get("packages", []):
                    pkg_info = pkg.get("package", {})
                    pkg_name = pkg_info.get("name")
                    pkg_ver = pkg_info.get("version")
                    for vuln in pkg.get("vulnerabilities", []):
                        vuln_id = vuln.get("id")
                        summary = vuln.get("summary") or f"Vulnerability {vuln_id} in {pkg_name}@{pkg_ver}"
                        findings.append(NormalizedFinding(
                            source="hexstrike",
                            tool="osv-scanner",
                            category="SCA",
                            severity="HIGH",
                            title=f"Vulnerable Dependency: {pkg_name} ({vuln_id})",
                            description=summary,
                            target=target,
                            cve=vuln_id if vuln_id.startswith("CVE-") else None,
                            evidence=f"Package: {pkg_name} Version: {pkg_ver}",
                            recommendation=f"Upgrade {pkg_name} to latest patched version.",
                            raw_data=vuln
                        ))
        except Exception:
            pass
        return findings

    @classmethod
    def _parse_trivy(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    findings.append(NormalizedFinding(
                        source="hexstrike",
                        tool="trivy",
                        category="SCA",
                        severity=vuln.get("Severity", "MEDIUM").upper(),
                        title=f"{vuln.get('PkgName')} - {vuln.get('VulnerabilityID')}",
                        description=vuln.get("Title") or vuln.get("Description") or "Trivy detected vulnerability.",
                        target=target,
                        cve=vuln.get("VulnerabilityID"),
                        evidence=f"Installed: {vuln.get('InstalledVersion')} Fixed: {vuln.get('FixedVersion')}",
                        recommendation=f"Upgrade {vuln.get('PkgName')} to version {vuln.get('FixedVersion', 'latest')}.",
                        raw_data=vuln
                    ))
        except Exception:
            pass
        return findings

    @classmethod
    def _parse_audit(cls, output: str, target: str, tool: str) -> List[NormalizedFinding]:
        findings = []
        try:
            data = json.loads(output)
            # General audit structure
            if tool == "pip-audit":
                deps = data.get("dependencies", [])
                for dep in deps:
                    for vuln in dep.get("vulns", []):
                        findings.append(NormalizedFinding(
                            source="hexstrike",
                            tool="pip-audit",
                            category="SCA",
                            severity="HIGH",
                            title=f"Vulnerable Python Package: {dep.get('name')}",
                            description=vuln.get("description") or f"Vulnerability {vuln.get('id')} in {dep.get('name')}",
                            target=target,
                            cve=vuln.get("id"),
                            recommendation=f"Upgrade {dep.get('name')} to safe version: {', '.join(vuln.get('fix_versions', []))}",
                            raw_data=vuln
                        ))
        except Exception:
            pass
        return findings

    @classmethod
    def _parse_ssl(cls, output: str, target: str, tool: str) -> List[NormalizedFinding]:
        findings = []
        # Check for SSL vulnerabilities (e.g. SSLv3, TLS 1.0, expired cert, weak cipher)
        lower = output.lower()
        if "tls 1.0" in lower and "offered" in lower or "tls1.0" in lower:
            findings.append(NormalizedFinding(
                source="hexstrike",
                tool=tool,
                category="SSL",
                severity="MEDIUM",
                title="Deprecated TLS 1.0 Protocol Enabled",
                description="The server supports deprecated TLS 1.0 protocol which lacks modern cryptographic protections.",
                target=target,
                recommendation="Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 exclusively."
            ))
        if "expired" in lower or "certificate has expired" in lower:
            findings.append(NormalizedFinding(
                source="hexstrike",
                tool=tool,
                category="SSL",
                severity="HIGH",
                title="SSL Certificate Expired",
                description="The SSL/TLS certificate for the domain is expired, causing browser security warnings.",
                target=target,
                recommendation="Renew the SSL/TLS certificate immediately."
            ))
        return findings

    @classmethod
    def _parse_recon(cls, output: str, target: str, tool: str) -> List[NormalizedFinding]:
        findings = []
        subdomains = [line.strip() for line in output.splitlines() if line.strip() and "." in line]
        if subdomains:
            findings.append(NormalizedFinding(
                source="hexstrike",
                tool=tool,
                category="RECON",
                severity="INFO",
                title=f"Discovered {len(subdomains)} Subdomains",
                description=f"{tool} discovered active subdomains under {target}: {', '.join(subdomains[:10])}...",
                target=target,
                evidence=f"Total subdomains: {len(subdomains)}",
                raw_data={"subdomains": subdomains}
            ))
        return findings

    @classmethod
    def _parse_wafw00f(cls, output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        m = re.search(r"is behind (.*?)(?:\(|$)", output, re.IGNORECASE)
        if m:
            waf_name = m.group(1).strip()
            findings.append(NormalizedFinding(
                source="hexstrike",
                tool="wafw00f",
                category="RECON",
                severity="INFO",
                title=f"WAF Detected: {waf_name}",
                description=f"Web Application Firewall detected protecting target: {waf_name}.",
                target=target,
                evidence=waf_name
            ))
        return findings

    @classmethod
    def _parse_generic(cls, output: str, target: str, tool: str, category: str, error: Optional[str] = None) -> List[NormalizedFinding]:
        if not output.strip():
            return []
        snippet = output[:300].strip()
        return [
            NormalizedFinding(
                source="hexstrike",
                tool=tool,
                category=category,
                severity="INFO",
                title=f"Scan Output from {tool.upper()}",
                description=snippet,
                target=target,
                raw_data={"raw": output, "error": error} if error else {"raw": output}
            )
        ]

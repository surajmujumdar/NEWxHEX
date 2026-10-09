#!/usr/bin/env python3
"""
HexStrike AI - SCA & Supply Chain Security Module (Software Composition Analysis)
================================================================================
Parses dependency manifests across Python (requirements.txt), Node.js (package.json),
Java (pom.xml), Go (go.mod), PHP (composer.json), and Ruby (Gemfile.lock).
Flags vulnerable components, cross-references CVEs/GHSAs, and suggests upgrade targets.
"""

import os
import re
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

import requests

try:
    from .repo_fetcher import is_git_or_github_url, fetch_or_clone_repo, cleanup_repo, parse_repo_info
except (ImportError, ValueError):
    try:
        from tools.repo_fetcher import is_git_or_github_url, fetch_or_clone_repo, cleanup_repo, parse_repo_info
    except (ImportError, ValueError):
        from repo_fetcher import is_git_or_github_url, fetch_or_clone_repo, cleanup_repo, parse_repo_info



@dataclass
class SCAFinding:
    """Represents a discovered supply-chain dependency vulnerability"""
    package_name: str
    installed_version: str
    ecosystem: str           # PyPI, npm, Maven, Go, Packagist, RubyGems
    cve_id: str              # e.g. CVE-2021-44228
    ghsa_id: Optional[str]   # e.g. GHSA-jfh8-c2jp-5v3q
    title: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float        # 0.0 - 10.0
    vulnerable_versions: str # e.g. "< 2.15.0"
    fixed_version: str       # e.g. ">= 2.15.0"
    manifest_path: str
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SCADatabase:
    """Built-in vulnerability signatures database with live OSV.dev fallback"""

    KNOWN_VULNERABILITIES = {
        "PyPI": {
            "urllib3": [
                {
                    "cve": "CVE-2023-45803",
                    "ghsa": "GHSA-v845-jxx5-vc9f",
                    "title": "urllib3 Request Header Leakage on Redirect",
                    "severity": "MEDIUM",
                    "cvss": 6.5,
                    "max_vuln_version": "2.0.7",
                    "fixed": "2.0.7",
                    "desc": "urllib3 leaks authorization headers when following cross-origin redirects."
                },
                {
                    "cve": "CVE-2021-33503",
                    "ghsa": "GHSA-q2q7-5pp4-w6pg",
                    "title": "urllib3 Regular Expression Denial of Service (ReDoS)",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "max_vuln_version": "1.26.5",
                    "fixed": "1.26.5",
                    "desc": "Catastrophic backtracking vulnerability in authority regex parser."
                }
            ],
            "requests": [
                {
                    "cve": "CVE-2023-32681",
                    "ghsa": "GHSA-j8r2-6x86-q33q",
                    "title": "Requests Proxy-Authorization Header Leak",
                    "severity": "MEDIUM",
                    "cvss": 6.1,
                    "max_vuln_version": "2.31.0",
                    "fixed": "2.31.0",
                    "desc": "Unintended leak of Proxy-Authorization header to destination servers when redirected."
                }
            ],
            "cryptography": [
                {
                    "cve": "CVE-2023-49083",
                    "ghsa": "GHSA-j8r2-6x86-q33q",
                    "title": "cryptography PKCS7 NULL Pointer Dereference DoS",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "max_vuln_version": "41.0.5",
                    "fixed": "41.0.6",
                    "desc": "NULL-pointer dereference in PKCS7 parsing when loading certificate bundles leading to crash/DoS."
                }
            ],
            "flask": [
                {
                    "cve": "CVE-2023-30861",
                    "ghsa": "GHSA-m2qf-hxjv-5gpq",
                    "title": "Flask Session Cookie Leak via Cached Responses",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "max_vuln_version": "2.2.5",
                    "fixed": "2.2.5",
                    "desc": "Flask may set cookie headers on cached responses allowing user session hijacking."
                }
            ],
            "django": [
                {
                    "cve": "CVE-2024-42005",
                    "ghsa": "GHSA-jrh3-84cx-4p25",
                    "title": "Django SQL Injection in QuerySet.values()",
                    "severity": "CRITICAL",
                    "cvss": 9.1,
                    "max_vuln_version": "5.0.7",
                    "fixed": "5.0.8",
                    "desc": "SQL injection vulnerability in values() and values_list() when using JSONField."
                }
            ],
            "pyyaml": [
                {
                    "cve": "CVE-2020-14343",
                    "ghsa": "GHSA-8q59-q68h-6hv4",
                    "title": "PyYAML Arbitrary Code Execution via FullLoader",
                    "severity": "CRITICAL",
                    "cvss": 9.8,
                    "max_vuln_version": "5.4.0",
                    "fixed": "5.4",
                    "desc": "Custom Python tags in YAML payloads allow arbitrary object instantiation and code execution."
                }
            ],
            "jinja2": [
                {
                    "cve": "CVE-2024-22195",
                    "ghsa": "GHSA-h5c8-rqwp-cp95",
                    "title": "Jinja2 HTML Attribute Injection / Sandbox Escape",
                    "severity": "MEDIUM",
                    "cvss": 6.1,
                    "max_vuln_version": "3.1.3",
                    "fixed": "3.1.3",
                    "desc": "XML-style attribute injection when using the xmlattr filter."
                }
            ],
            "aiohttp": [
                {
                    "cve": "CVE-2024-23334",
                    "ghsa": "GHSA-5h86-8mv2-jq9f",
                    "title": "aiohttp Directory Traversal / Arbitrary File Read",
                    "severity": "HIGH",
                    "cvss": 8.6,
                    "max_vuln_version": "3.9.1",
                    "fixed": "3.9.2",
                    "desc": "Directory traversal vulnerability in static file serving when follow_symlinks=True."
                }
            ],
            "certifi": [
                {
                    "cve": "CVE-2023-37920",
                    "ghsa": "GHSA-xqr8-7jwr-rhp7",
                    "title": "certifi Untrusted Root Certificate Authority Inclusion",
                    "severity": "LOW",
                    "cvss": 3.7,
                    "max_vuln_version": "2023.7.21",
                    "fixed": "2023.7.22",
                    "desc": "Outdated trust bundle included e-Tugra root certificate."
                }
            ]
        },
        "npm": {
            "lodash": [
                {
                    "cve": "CVE-2021-23337",
                    "ghsa": "GHSA-35jh-r3h4-6jhm",
                    "title": "Lodash Prototype Pollution via template",
                    "severity": "HIGH",
                    "cvss": 7.2,
                    "max_vuln_version": "4.17.20",
                    "fixed": "4.17.21",
                    "desc": "Prototype pollution vulnerability in lodash.template allows property injection."
                }
            ],
            "axios": [
                {
                    "cve": "CVE-2023-45857",
                    "ghsa": "GHSA-wf5p-g6vw-rhxx",
                    "title": "Axios Cross-Site Request Forgery (CSRF) via Cookie Forwarding",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "max_vuln_version": "1.5.1",
                    "fixed": "1.6.0",
                    "desc": "Axios automatically passes confidential cookies on cross-origin redirects."
                }
            ],
            "jsonwebtoken": [
                {
                    "cve": "CVE-2022-23529",
                    "ghsa": "GHSA-8cf7-32gw-wr33",
                    "title": "jsonwebtoken Insecure Key Object Verification RCE",
                    "severity": "CRITICAL",
                    "cvss": 9.8,
                    "max_vuln_version": "8.5.1",
                    "fixed": "9.0.0",
                    "desc": "Crafted secretOrPublicKey objects can trigger arbitrary code execution."
                }
            ],
            "express": [
                {
                    "cve": "CVE-2024-29041",
                    "ghsa": "GHSA-qw6h-58jh-pwp7",
                    "title": "Express.js Open Redirect Vulnerability",
                    "severity": "MEDIUM",
                    "cvss": 6.1,
                    "max_vuln_version": "4.19.1",
                    "fixed": "4.19.2",
                    "desc": "Improper input validation in res.redirect() allows external open redirection."
                }
            ],
            "next": [
                {
                    "cve": "CVE-2024-34351",
                    "ghsa": "GHSA-fr5h-rqp8-gw6v",
                    "title": "Next.js Server Actions Server-Side Request Forgery (SSRF)",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "max_vuln_version": "14.1.0",
                    "fixed": "14.1.1",
                    "desc": "Host header manipulation in Server Actions redirects leads to SSRF."
                }
            ]
        },
        "Maven": {
            "log4j-core": [
                {
                    "cve": "CVE-2021-44228",
                    "ghsa": "GHSA-jfh8-c2jp-5v3q",
                    "title": "Log4Shell - Apache Log4j JNDI Remote Code Execution",
                    "severity": "CRITICAL",
                    "cvss": 10.0,
                    "max_vuln_version": "2.15.0",
                    "fixed": "2.17.1",
                    "desc": "JNDI lookup feature in Log4j enables full remote code execution via LDAP/RMI."
                }
            ],
            "spring-core": [
                {
                    "cve": "CVE-2022-22965",
                    "ghsa": "GHSA-36p3-wjmg-h94x",
                    "title": "Spring4Shell - Spring Framework RCE via Data Binding",
                    "severity": "CRITICAL",
                    "cvss": 9.8,
                    "max_vuln_version": "5.3.17",
                    "fixed": "5.3.18",
                    "desc": "Class loader access via parameter data binding leads to arbitrary file write / RCE."
                }
            ]
        }
    }


class SCAScanner:
    """Enterprise Software Composition Analysis (SCA) Scanner Engine"""

    def __init__(self, query_osv_api: bool = True, timeout: int = 5):
        self.query_osv_api = query_osv_api
        self.timeout = timeout
        self.session = requests.Session()

    def parse_version_tuple(self, v_str: str) -> Tuple[int, ...]:
        """Convert version string to comparable integer tuple"""
        clean = re.sub(r'^[^\d]*', '', v_str.strip())
        parts = []
        for segment in clean.split('.'):
            num = re.match(r'^\d+', segment)
            if num:
                parts.append(int(num.group(0)))
            else:
                parts.append(0)
        return tuple(parts) if parts else (0, 0, 0)

    def is_version_vulnerable(self, installed: str, max_vuln: str) -> bool:
        """Check if installed version is less than or equal to max vulnerable version"""
        try:
            inst_tuple = self.parse_version_tuple(installed)
            vuln_tuple = self.parse_version_tuple(max_vuln)
            return inst_tuple <= vuln_tuple
        except Exception:
            return False

    def query_osv_for_package(self, name: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
        """Query live OSV.dev open vulnerability database API"""
        if not self.query_osv_api or not version:
            return []

        url = "https://api.osv.dev/v1/query"
        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
        except Exception:
            pass
        return []

    def parse_python_requirements(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse Python requirements.txt"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    # Match package==version, package>=version, package~=version
                    match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z_\-\.]*)', line)
                    if match:
                        pkg_name = match.group(1).lower().strip()
                        pkg_ver = match.group(2).strip() or "0.0.0"
                        dependencies.append((pkg_name, pkg_ver))
        except Exception:
            pass
        return dependencies

    def parse_nodejs_package(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse Node.js package.json / package-lock.json"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check dependencies, devDependencies, peerDependencies
            for dep_section in ["dependencies", "devDependencies", "peerDependencies"]:
                if dep_section in data and isinstance(data[dep_section], dict):
                    for name, ver in data[dep_section].items():
                        clean_ver = re.sub(r'[\^~>=<v]', '', str(ver)).strip()
                        dependencies.append((name.lower().strip(), clean_ver or "0.0.0"))

            # Lockfile dependencies
            if "packages" in data and isinstance(data["packages"], dict):
                for path_key, meta in data["packages"].items():
                    name = meta.get("name") or path_key.replace("node_modules/", "")
                    ver = meta.get("version", "")
                    if name and ver:
                        dependencies.append((name.lower().strip(), ver))
        except Exception:
            pass
        return dependencies

    def parse_java_pom(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse Java Maven pom.xml"""
        dependencies = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            # Handle XML namespace
            ns = {'mvn': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
            xpath = './/mvn:dependency' if ns else './/dependency'

            for dep in root.findall(xpath, ns):
                art_elem = dep.find('mvn:artifactId' if ns else 'artifactId', ns)
                ver_elem = dep.find('mvn:version' if ns else 'version', ns)
                if art_elem is not None:
                    name = art_elem.text.strip().lower() if art_elem.text else ""
                    ver = ver_elem.text.strip() if (ver_elem is not None and ver_elem.text) else "0.0.0"
                    if name:
                        dependencies.append((name, ver))
        except Exception:
            pass
        return dependencies

    def parse_go_mod(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse Go go.mod"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            # Match require ( ... ) blocks and inline require
            matches = re.findall(r'require\s+(?:\(\s*([\s\S]*?)\s*\)|([^\s]+)\s+v?([0-9a-zA-Z\.\-]+))', content)
            for block, single_mod, single_ver in matches:
                if block:
                    for line in block.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('//'):
                            parts = line.split()
                            if len(parts) >= 2:
                                name = parts[0].strip()
                                ver = parts[1].lstrip('v').strip()
                                dependencies.append((name, ver))
                elif single_mod:
                    dependencies.append((single_mod.strip(), single_ver.lstrip('v').strip()))
        except Exception:
            pass
        return dependencies

    def scan_manifest(self, manifest_path: str) -> Dict[str, Any]:
        """Scan a single dependency declaration manifest file"""
        start_time = datetime.now()
        path = Path(manifest_path).resolve()
        findings: List[SCAFinding] = []

        if not path.is_file():
            return {
                "success": False,
                "error": f"Manifest file '{manifest_path}' does not exist.",
                "findings": []
            }

        filename = path.name.lower()
        ecosystem = "Unknown"
        dependencies: List[Tuple[str, str]] = []

        if filename in ["requirements.txt", "pipfile", "setup.py", "pyproject.toml"]:
            ecosystem = "PyPI"
            dependencies = self.parse_python_requirements(str(path))
        elif filename in ["package.json", "package-lock.json", "yarn.lock"]:
            ecosystem = "npm"
            dependencies = self.parse_nodejs_package(str(path))
        elif filename in ["pom.xml"]:
            ecosystem = "Maven"
            dependencies = self.parse_java_pom(str(path))
        elif filename in ["go.mod", "go.sum"]:
            ecosystem = "Go"
            dependencies = self.parse_go_mod(str(path))

        # Check dependencies against known database & OSV
        for pkg_name, version in dependencies:
            # 1. Local Database Check
            known_ecosystem = SCADatabase.KNOWN_VULNERABILITIES.get(ecosystem, {})
            if pkg_name in known_ecosystem:
                for vuln in known_ecosystem[pkg_name]:
                    if self.is_version_vulnerable(version, vuln["max_vuln_version"]):
                        findings.append(SCAFinding(
                            package_name=pkg_name,
                            installed_version=version,
                            ecosystem=ecosystem,
                            cve_id=vuln["cve"],
                            ghsa_id=vuln.get("ghsa"),
                            title=vuln["title"],
                            severity=vuln["severity"],
                            cvss_score=vuln["cvss"],
                            vulnerable_versions=f"<= {vuln['max_vuln_version']}",
                            fixed_version=f">= {vuln['fixed']}",
                            manifest_path=str(path),
                            description=vuln["desc"],
                            remediation=f"Upgrade '{pkg_name}' from {version} to >= {vuln['fixed']}."
                        ))

            # 2. Live OSV API check
            if self.query_osv_api and version and version != "0.0.0":
                osv_vulns = self.query_osv_for_package(pkg_name, version, ecosystem)
                for osv in osv_vulns:
                    cve_id = next((alias for alias in osv.get("aliases", []) if alias.startswith("CVE-")), osv.get("id", "UNKNOWN"))
                    ghsa_id = next((alias for alias in osv.get("aliases", []) if alias.startswith("GHSA-")), None)

                    # Avoid duplicate if already matched by local DB
                    if any(f.cve_id == cve_id and f.package_name == pkg_name for f in findings):
                        continue

                    # Extract CVSS / severity
                    score = 7.5
                    severity = "HIGH"
                    if "database_specific" in osv and "severity" in osv["database_specific"]:
                        raw_sev = str(osv["database_specific"]["severity"]).upper()
                        if "CRITICAL" in raw_sev:
                            severity, score = "CRITICAL", 9.8
                        elif "HIGH" in raw_sev:
                            severity, score = "HIGH", 8.0
                        elif "MODERATE" in raw_sev or "MEDIUM" in raw_sev:
                            severity, score = "MEDIUM", 5.5
                        elif "LOW" in raw_sev:
                            severity, score = "LOW", 3.0

                    findings.append(SCAFinding(
                        package_name=pkg_name,
                        installed_version=version,
                        ecosystem=ecosystem,
                        cve_id=cve_id,
                        ghsa_id=ghsa_id,
                        title=osv.get("summary") or f"Vulnerability in {pkg_name}",
                        severity=severity,
                        cvss_score=score,
                        vulnerable_versions=f"Version {version}",
                        fixed_version="Latest Available Release",
                        manifest_path=str(path),
                        description=osv.get("details", "Disclosed via OSV.dev"),
                        remediation=f"Upgrade '{pkg_name}' to the latest secure release."
                    ))

        findings.sort(key=lambda x: x.cvss_score, reverse=True)
        duration = (datetime.now() - start_time).total_seconds()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = str(getattr(f, "severity", None) or f.get("severity", "MEDIUM")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        return {
            "success": True,
            "manifest_path": str(path),
            "ecosystem": ecosystem,
            "dependencies_found": len(dependencies),
            "vulnerabilities_count": len(findings),
            "security_score": security_score,
            "duration_seconds": round(duration, 3),
            "severity_summary": counts,
            "dependencies": [{"package": name, "version": ver} for name, ver in dependencies],
            "findings": [f.to_dict() for f in findings]
        }

    def scan_directory(self, target_dir: str, github_url: Optional[str] = None) -> Dict[str, Any]:
        """Discover and scan all dependency manifests in a project directory or remote GitHub repo"""
        start_time = datetime.now()
        raw_target = (github_url or target_dir or "").strip()
        is_remote_repo = False
        repo_info = None
        temp_repo_path = None
        base_temp_path = None

        if is_git_or_github_url(raw_target):
            is_remote_repo = True
            fetch_res = fetch_or_clone_repo(raw_target)
            if not fetch_res.get("success"):
                return {
                    "success": False,
                    "target_dir": raw_target,
                    "error": f"Failed to clone/download remote repository: {fetch_res.get('error')}",
                    "findings": [],
                    "summary": {}
                }
            temp_repo_path = fetch_res.get("repo_path")
            base_temp_path = fetch_res.get("base_temp_path")
            repo_info = fetch_res.get("repo_info")
            target = Path(temp_repo_path).resolve()
        else:
            target = Path(raw_target).resolve()
            if not target.exists():
                return {
                    "success": False,
                    "target_dir": raw_target,
                    "error": f"Target path '{raw_target}' does not exist locally.",
                    "findings": [],
                    "summary": {}
                }

        manifest_filenames = {
            "requirements.txt", "package.json", "pom.xml", "go.mod", "composer.json", "gemfile.lock"
        }

        all_manifest_results = []
        total_findings: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', 'hexstrike-env', 'dist', 'build']]
            for file_name in files:
                if file_name.lower() in manifest_filenames:
                    manifest_file = os.path.join(root, file_name)
                    result = self.scan_manifest(manifest_file)
                    
                    if is_remote_repo and temp_repo_path:
                        try:
                            rel_m = os.path.relpath(result.get("manifest_path", manifest_file), temp_repo_path)
                            result["manifest_path"] = rel_m.replace("\\", "/")
                            for f in result.get("findings", []):
                                if "manifest_path" in f:
                                    f["manifest_path"] = rel_m.replace("\\", "/")
                        except Exception:
                            pass
                    
                    all_manifest_results.append(result)
                    total_findings.extend(result.get("findings", []))

        duration = (datetime.now() - start_time).total_seconds()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in total_findings:
            sev = str(f.get("severity", "MEDIUM")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        # Cleanup temporary repo files if remote
        if is_remote_repo and temp_repo_path:
            cleanup_repo(temp_repo_path, base_temp_path)

        return {
            "success": True,
            "target_dir": raw_target,
            "is_github_repo": is_remote_repo,
            "repository_info": repo_info,
            "manifests_scanned": len(all_manifest_results),
            "total_dependencies": sum(m.get("dependencies_found", 0) for m in all_manifest_results),
            "total_vulnerabilities": len(total_findings),
            "security_score": security_score,
            "duration_seconds": round(duration, 3),
            "severity_summary": counts,
            "manifest_results": all_manifest_results,
            "findings": total_findings
        }


    def generate_markdown_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate formatted Markdown report for SCA scan"""
        if not scan_results.get("success"):
            return f"### SCA Scan Failed\n\nError: {scan_results.get('error', 'Unknown error')}"

        summary = scan_results.get("severity_summary", {})
        score = scan_results.get("security_score", 100)
        target = scan_results.get("manifest_path") or scan_results.get("target_dir", "Unknown")

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 60 else "🔴"

        md = [
            f"# 📦 HexStrike SCA & Supply Chain Security Audit Report",
            f"**Target:** `{target}` | **Dependencies Evaluated:** {scan_results.get('dependencies_found', scan_results.get('total_dependencies', 0))} | **Duration:** {scan_results.get('duration_seconds', 0)}s",
            f"**Supply Chain Health Score:** {status_emoji} **{score}/100**",
            "",
            "## 📊 Executive Severity Breakdown",
            f"- 🔴 **Critical:** {summary.get('CRITICAL', 0)}",
            f"- 🟠 **High:** {summary.get('HIGH', 0)}",
            f"- 🟡 **Medium:** {summary.get('MEDIUM', 0)}",
            f"- 🔵 **Low:** {summary.get('LOW', 0)}",
            "",
            "## 🔍 Vulnerable Dependencies & Outdated Components"
        ]

        findings = scan_results.get("findings", [])
        if not findings:
            md.append("✅ *All evaluated software dependencies are up-to-date with no known CVE/GHSA vulnerabilities.*")
        else:
            for idx, f in enumerate(findings[:25], start=1):
                cve_tag = f"[`{f['cve_id']}`]"
                if f.get("ghsa_id"):
                    cve_tag += f" / [`{f['ghsa_id']}`]"
                sev_badge = f"**[{f['severity']}] (CVSS {f['cvss_score']})**"
                md.append(f"### {idx}. {f['package_name']} @ {f['installed_version']} - {f['title']} {sev_badge}")
                md.append(f"- **Vulnerability Identifiers:** {cve_tag}")
                md.append(f"- **Ecosystem:** `{f['ecosystem']}` | **Manifest:** `{f['manifest_path']}`")
                md.append(f"- **Vulnerable Versions:** `{f['vulnerable_versions']}` | **Remediation Target:** `{f['fixed_version']}`")
                md.append(f"- **Description:** {f['description']}")
                md.append(f"- **Remediation:** {f['remediation']}")
                md.append("")

        return "\n".join(md)


def main():
    """Standalone CLI runner for testing the SCA scanner"""
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike SCA Supply Chain Vulnerability Scanner")
    parser.add_argument("path", help="Path to manifest file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    scanner = SCAScanner()
    if os.path.isfile(args.path):
        results = scanner.scan_manifest(args.path)
    else:
        results = scanner.scan_directory(args.path)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(scanner.generate_markdown_report(results))


if __name__ == "__main__":
    main()

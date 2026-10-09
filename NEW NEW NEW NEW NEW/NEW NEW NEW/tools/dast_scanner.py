#!/usr/bin/env python3
"""
HexStrike AI - Comprehensive DAST Scanner Module (Dynamic Application Security Testing)
======================================================================================
Performs runtime web application vulnerability assessments, security misconfiguration audits,
header compliance checks, sensitive file exposure discovery, and passive/active injection probing.
"""

import re
import sys
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

import requests
from bs4 import BeautifulSoup


@dataclass
class DASTFinding:
    """Represents a single dynamic application security finding"""
    id: str
    title: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float      # 0.0 - 10.0
    owasp_category: str    # e.g. A05:2021-Security Misconfiguration
    cwe_id: str            # e.g. CWE-200
    target_url: str
    parameter: Optional[str]
    evidence: str
    description: str
    remediation: str
    confidence: str        # HIGH, MEDIUM, LOW

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DASTScanner:
    """Enterprise Dynamic Application Security Testing (DAST) Engine"""

    SENSITIVE_FILES = [
        "/.env",
        "/.git/HEAD",
        "/.git/config",
        "/.gitignore",
        "/robots.txt",
        "/sitemap.xml",
        "/docker-compose.yml",
        "/Dockerfile",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/config.json",
        "/settings.json",
        "/.DS_Store",
        "/package.json",
        "/composer.json",
        "/web.config",
        "/.htaccess",
        "/phpinfo.php",
        "/actuator/health",
        "/actuator/env",
        "/server-status"
    ]

    REQUIRED_SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "title": "Missing Content-Security-Policy (CSP) Header",
            "severity": "MEDIUM",
            "cvss": 5.4,
            "cwe": "CWE-1021",
            "owasp": "A05:2021-Security Misconfiguration",
            "desc": "The Content-Security-Policy HTTP header is missing. CSP restricts script execution sources to prevent Cross-Site Scripting (XSS) and data injection.",
            "remediation": "Configure a strong Content-Security-Policy header restricting script-src, style-src, and default-src."
        },
        "Strict-Transport-Security": {
            "title": "Missing HTTP Strict Transport Security (HSTS) Header",
            "severity": "MEDIUM",
            "cvss": 4.8,
            "cwe": "CWE-319",
            "owasp": "A02:2021-Cryptographic Failures",
            "desc": "The Strict-Transport-Security header is not set. Browsers may establish unencrypted HTTP connections susceptible to SSL-stripping MITM attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
        },
        "X-Frame-Options": {
            "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
            "severity": "MEDIUM",
            "cvss": 5.4,
            "cwe": "CWE-1021",
            "owasp": "A05:2021-Security Misconfiguration",
            "desc": "X-Frame-Options is not configured, allowing the web page to be embedded in an <iframe> and targeted with clickjacking attacks.",
            "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
        },
        "X-Content-Type-Options": {
            "title": "Missing X-Content-Type-Options Header",
            "severity": "LOW",
            "cvss": 3.7,
            "cwe": "CWE-79",
            "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Missing 'X-Content-Type-Options: nosniff'. Browsers may MIME-sniff responses away from the declared content type.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses."
        },
        "Referrer-Policy": {
            "title": "Missing Referrer-Policy Header",
            "severity": "LOW",
            "cvss": 3.1,
            "cwe": "CWE-116",
            "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Referrer-Policy is not specified, potentially leaking sensitive URL tokens or paths in outbound referrer headers.",
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
        },
        "Permissions-Policy": {
            "title": "Missing Permissions-Policy Header",
            "severity": "LOW",
            "cvss": 2.7,
            "cwe": "CWE-16",
            "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Permissions-Policy (formerly Feature-Policy) is not defined, leaving browser device capabilities (camera, microphone, geolocation) unconstrained.",
            "remediation": "Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        }
    }

    SQLI_ERROR_SIGNATURES = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\bmysql_",
        r"valid MySQL result",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\bpg_",
        r"valid PostgreSQL result",
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"ORA-\d{5}",
        r"Oracle error",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Unclosed quotation mark before the character string",
        r"syntax error in string in query expression"
    ]

    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "server": ["cloudflare"],
            "body": ["protected by cloudflare", "cloudflare ray id", "attention required! | cloudflare", "just a moment..."],
            "cookies": ["__cfduid", "__cf_bm", "cf_clearance"]
        },
        "AWS WAF": {
            "headers": ["x-amzn-waf-action", "x-amzn-requestid", "x-amz-cf-id", "x-amzn-errortype"],
            "server": ["awselb", "amazon"],
            "body": ["aws waf", "request blocked by aws waf", "403 forbidden - aws waf"],
            "cookies": ["aws-waf-token"]
        },
        "Akamai Edge": {
            "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id", "x-check-cacheable"],
            "server": ["akamaighost", "akamai"],
            "body": ["access denied - akamai", "akamai error", "reference&#32;&#35;"],
            "cookies": ["ak_bmsc", "bm_sz", "_abck"]
        },
        "Imperva / Incapsula": {
            "headers": ["x-iinfo", "x-cdn", "incap_ses", "visid_incap"],
            "server": ["incapsula"],
            "body": ["incapsula incident id", "powered by incapsula", "_incapsula_resource"],
            "cookies": ["visid_incap", "incap_ses"]
        },
        "Sucuri CloudProxy": {
            "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
            "server": ["sucuri/cloudproxy", "sucuri"],
            "body": ["access denied - sucuri website firewall", "sucuri.net", "cloudproxy"],
            "cookies": ["sucuri_cloudproxy"]
        },
        "ModSecurity / OWASP CRS": {
            "headers": ["x-mod-sec", "x-modsecurity", "mod_security"],
            "server": ["mod_security", "modsecurity", "noyb"],
            "body": ["modsecurity action", "modsecurity: access denied", "this error was generated by mod_security", "owasp modsecurity core rule set"],
            "cookies": []
        },
        "F5 BIG-IP ASM": {
            "headers": ["x-cnection", "x-wa-info"],
            "server": ["big-ip", "bigip", "f5"],
            "body": ["the requested url was rejected. please consult with your administrator", "ts01"],
            "cookies": ["ts", "f5_cspm", "bigipserver"]
        },
        "Fortinet FortiWeb": {
            "headers": ["x-fortiweb", "fortiwaf"],
            "server": ["fortiweb"],
            "body": ["fortiweb", "customized fortiweb block page"],
            "cookies": ["fortiwafid"]
        },
        "DataDome": {
            "headers": ["x-datadome", "x-datadome-response"],
            "server": ["datadome"],
            "body": ["datadome captcha", "protected by datadome"],
            "cookies": ["datadome"]
        },
        "Fastly / Signal Sciences": {
            "headers": ["x-fastly-request-id", "fastly-restarts", "x-sigsci-request-id"],
            "server": ["fastly"],
            "body": ["fastly error: unknown domain", "signal sciences"],
            "cookies": []
        },
        "Wordfence": {
            "headers": ["x-wordfence"],
            "server": [],
            "body": ["generated by wordfence", "your access to this site has been limited by wordfence"],
            "cookies": ["wfvt_", "wordfence_lh"]
        },
        "Barracuda WAF": {
            "headers": ["x-barracuda-", "barra_counter_session"],
            "server": ["barracuda"],
            "body": ["you have been blocked by the barracuda web application firewall"],
            "cookies": ["barra_counter_session", "bni__barracuda_lb_cookie"]
        },
        "Microsoft Azure WAF / Front Door": {
            "headers": ["x-azure-ref", "x-ms-request-id", "x-azure-fdid"],
            "server": ["microsoft-iis"],
            "body": ["azure front door", "request blocked by azure"],
            "cookies": []
        }
    }

    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        })

    def detect_waf(self, resp: Optional[requests.Response]) -> Tuple[Optional[str], str, List[str]]:
        """Inspect response headers, status codes, cookies, and body patterns for WAF/Firewall signatures"""
        if resp is None:
            return None, "NONE", []

        matched_signatures = []
        detected_vendor = None
        confidence = "LOW"

        headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
        cookies_lower = []
        if hasattr(resp, "cookies") and resp.cookies is not None:
            try:
                for c in resp.cookies:
                    if hasattr(c, "name"):
                        cookies_lower.append(str(c.name).lower())
                    elif isinstance(c, str):
                        cookies_lower.append(c.lower())
            except Exception:
                pass
        server_banner = headers_lower.get("server", "")
        body_sample = resp.text[:4000].lower() if hasattr(resp, "text") and resp.text else ""

        for vendor, sigs in self.WAF_SIGNATURES.items():
            vendor_matches = []
            # Check headers
            for h in sigs.get("headers", []):
                h_lower = h.lower()
                if h_lower in headers_lower:
                    vendor_matches.append(f"Header: {h}={headers_lower[h_lower]}")
                elif any(h_lower in k for k in headers_lower.keys()):
                    vendor_matches.append(f"Header pattern: {h}")

            # Check server banner
            for s in sigs.get("server", []):
                if s.lower() in server_banner:
                    vendor_matches.append(f"Server header: {server_banner}")

            # Check cookies
            for c in sigs.get("cookies", []):
                if any(c.lower() in ck for ck in cookies_lower):
                    vendor_matches.append(f"Cookie: {c}")

            # Check body text
            for b in sigs.get("body", []):
                if b.lower() in body_sample:
                    vendor_matches.append(f"Body signature: '{b}'")

            if vendor_matches:
                detected_vendor = vendor
                matched_signatures.extend(vendor_matches)
                confidence = "CONFIRMED" if len(vendor_matches) >= 2 or any("Header:" in m for m in vendor_matches) else "HIGH"
                break

        # Check generic firewall headers if no specific vendor matched
        if not detected_vendor:
            generic_fw_headers = ["x-firewall", "x-waf-status", "x-denied-reason", "x-block-reason", "x-security-policy", "x-envoy-decorator-operation"]
            for gh in generic_fw_headers:
                if gh in headers_lower:
                    detected_vendor = "Generic Web Application Firewall / Edge Proxy"
                    matched_signatures.append(f"Header: {gh}={headers_lower[gh]}")
                    confidence = "MEDIUM"

            if resp.status_code in [403, 429, 406] and ("firewall" in body_sample or "waf" in body_sample or "access denied" in body_sample or "security policy" in body_sample):
                detected_vendor = detected_vendor or "Perimeter Security Firewall"
                matched_signatures.append(f"HTTP {resp.status_code} with security block body content")
                confidence = "HIGH"

        return detected_vendor, confidence, matched_signatures

    def scan_target(
        self,
        target_url: str,
        auth_token: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        check_sensitive_files: bool = True,
        max_crawl_pages: int = 5
    ) -> Dict[str, Any]:
        """Perform comprehensive dynamic security analysis against a target URL"""
        start_time = datetime.now()
        findings: List[DASTFinding] = []

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        headers = custom_headers or {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}" if not auth_token.startswith("Bearer ") else auth_token

        # 1. Base Request & Security Headers Check
        try:
            resp = self.session.get(target_url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            err_str = str(e)
            is_timeout = isinstance(e, requests.exceptions.Timeout) or "timed out" in err_str.lower() or "timeout" in err_str.lower()
            is_ssl = isinstance(e, requests.exceptions.SSLError) or "ssl" in err_str.lower() or "certificate" in err_str.lower()
            is_refused = "connection refused" in err_str.lower() or "actively refused" in err_str.lower()

            if is_timeout:
                finding = DASTFinding(
                    id="DAST-NET-TIMEOUT",
                    title="Target Connection Timeout / Server Latency Warning",
                    severity="LOW",
                    cvss_score=3.0,
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-400",
                    target_url=target_url,
                    parameter=None,
                    evidence=f"Connection timed out after {self.timeout}s ({err_str})",
                    description=f"The target host failed to respond within {self.timeout}s. This may be caused by high backend latency, cold-start dynos/containers, or network congestion.",
                    remediation="Verify target host health, inspect web server logs, and ensure backend application services are active and responsive.",
                    confidence="MEDIUM"
                )
                telemetry = {
                    "waf_detected": False,
                    "waf_blocked": False,
                    "waf_vendor": "None Detected (Connection Timeout)",
                    "confidence": "NONE",
                    "matched_signatures": [],
                    "total_probes_blocked": 0,
                    "blocked_events": [],
                    "status_summary": f"Connection timed out after {self.timeout}s ({err_str})",
                    "audit_recommendation": "Check target server health and latency."
                }
            elif is_ssl:
                finding = DASTFinding(
                    id="DAST-SSL-FAIL",
                    title="SSL/TLS Handshake Failure / Cipher Suite Negotiation Rejection",
                    severity="HIGH",
                    cvss_score=7.4,
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-295",
                    target_url=target_url,
                    parameter=None,
                    evidence=f"TLS handshake failed: {err_str}",
                    description=f"The target server rejected the TLS handshake or presented an untrusted certificate chain: {err_str}",
                    remediation="1. Verify target server SSL/TLS certificate validity and trust chain.\n2. Ensure modern cipher suites (TLS 1.2/1.3) are enabled.\n3. If using custom internal CA, provide CA bundle to scanner.",
                    confidence="CONFIRMED"
                )
                telemetry = {
                    "waf_detected": False,
                    "waf_blocked": False,
                    "waf_vendor": "None Detected (TLS Termination / Handshake Error)",
                    "confidence": "NONE",
                    "matched_signatures": [f"TLS Handshake Failure: {err_str}"],
                    "total_probes_blocked": 0,
                    "blocked_events": [],
                    "status_summary": f"SSL/TLS Handshake failure: {err_str}",
                    "audit_recommendation": "Inspect SSL certificate validity and cryptographic cipher configurations."
                }
            elif is_refused:
                finding = DASTFinding(
                    id="DAST-NET-REFUSED",
                    title="Target Connection Refused / Service Port Closed",
                    severity="LOW",
                    cvss_score=3.0,
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-693",
                    target_url=target_url,
                    parameter=None,
                    evidence=f"Connection refused / port closed: {err_str}",
                    description=f"Target server actively refused connection or no service is listening on port: {err_str}",
                    remediation="1. Ensure target service is running and listening on port.\n2. Verify routing and firewall access rules.",
                    confidence="HIGH"
                )
                telemetry = {
                    "waf_detected": False,
                    "waf_blocked": False,
                    "waf_vendor": "None Detected (Connection Refused)",
                    "confidence": "NONE",
                    "matched_signatures": [],
                    "total_probes_blocked": 0,
                    "blocked_events": [],
                    "status_summary": f"Port connection refused ({err_str})",
                    "audit_recommendation": "Verify host availability and target service state."
                }
            else:
                finding = DASTFinding(
                    id="DAST-NET-ERR-001",
                    title="Target Unreachable / Network Transmission Failure",
                    severity="LOW",
                    cvss_score=2.0,
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-693",
                    target_url=target_url,
                    parameter=None,
                    evidence=f"Network error: {err_str}",
                    description=f"An error occurred while establishing a network connection to {target_url}: {err_str}",
                    remediation="Verify network routing, DNS records, and firewall accessibility.",
                    confidence="MEDIUM"
                )
                telemetry = {
                    "waf_detected": False,
                    "waf_vendor": "Connection Failed",
                    "confidence": "NONE",
                    "matched_signatures": [],
                    "total_probes_blocked": 0,
                    "blocked_events": [],
                    "status_summary": f"Network error: {err_str}",
                    "audit_recommendation": "Check network routing and target host state."
                }

            diag_findings = [finding]
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            counts[finding.severity] = 1
            deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
            security_score = max(0, 100 - deductions)

            result_obj = {
                "success": True,
                "target_url": target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "duration_seconds": round((datetime.now() - start_time).total_seconds(), 3),
                "http_status": 0,
                "security_score": security_score,
                "total_findings": 1,
                "severity_summary": counts,
                "firewall_waf_telemetry": telemetry,
                "findings": [f.to_dict() for f in diag_findings],
                "error": f"Connection diagnostic: {err_str}"
            }
            result_obj["markdown_report"] = self.generate_markdown_report(result_obj)
            return result_obj

        # Initialize WAF & Firewall Telemetry tracking
        blocked_events: List[Dict[str, Any]] = []
        waf_vendor, waf_confidence, waf_signatures = self.detect_waf(resp)

        # If target returns HTTP 503 Service Unavailable / Application Error
        if resp.status_code == 503:
            findings.append(DASTFinding(
                id="DAST-SRV-503",
                title="Target Service Unavailable / Backend Application Error (HTTP 503)",
                severity="MEDIUM",
                cvss_score=5.3,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-754",
                target_url=target_url,
                parameter=None,
                evidence=f"HTTP 503 Service Unavailable returned by web server (Server: {resp.headers.get('Server', 'Unknown')}). Body preview: {resp.text[:180].strip() if resp.text else ''}",
                description="The target web server returned HTTP 503 Service Unavailable or Application Error. This indicates backend dyno/container failure, resource exhaustion, or unhandled server crash.",
                remediation="Check server logs and application health metrics. Ensure application runtime processes are active and database connections are healthy.",
                confidence="CONFIRMED"
            ))

        # If target returns HTTP 500 Internal Server Error
        elif resp.status_code == 500:
            findings.append(DASTFinding(
                id="DAST-SRV-500",
                title="Internal Server Error (HTTP 500) Exposed on Target",
                severity="MEDIUM",
                cvss_score=5.0,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-754",
                target_url=target_url,
                parameter=None,
                evidence=f"HTTP 500 Internal Server Error returned by web server (Server: {resp.headers.get('Server', 'Unknown')}).",
                description="The web server encountered an unhandled exception or internal error while handling the request.",
                remediation="Implement robust global exception handlers and avoid leaking unhandled error responses to external clients.",
                confidence="CONFIRMED"
            ))

        # If initial request was blocked by an identified WAF or rate-limiter
        if (resp.status_code in [403, 406] and waf_vendor) or (resp.status_code == 429):
            blocked_events.append({
                "timestamp": datetime.now().isoformat(),
                "url": target_url,
                "method": "GET",
                "status_code": resp.status_code,
                "reason": "Root Target Access Denied (HTTP 403)" if resp.status_code == 403 else "Rate Limiting Throttling (HTTP 429)" if resp.status_code == 429 else f"Perimeter Block (HTTP {resp.status_code})",
                "waf_vendor": waf_vendor or "Rate-Limiting Edge Shield",
                "waf_signature": ", ".join(waf_signatures) if waf_signatures else f"HTTP {resp.status_code}",
                "evidence": resp.text[:200].strip() if resp.text else ""
            })

        # Check HTTP / HTTPS usage
        if parsed.scheme == "http":
            findings.append(DASTFinding(
                id="DAST-NET-001",
                title="Insecure Plaintext HTTP Protocol Used",
                severity="HIGH",
                cvss_score=7.4,
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-319",
                target_url=target_url,
                parameter=None,
                evidence=f"Target URL scheme is {parsed.scheme}",
                description="The target application serves traffic over unencrypted HTTP, allowing interception or tampering of credentials and session tokens.",
                remediation="Enforce HTTPS with automatic 301 redirects and implement HSTS.",
                confidence="HIGH"
            ))

        # 2. Audit Missing Security Headers
        resp_headers = resp.headers
        for header_name, meta in self.REQUIRED_SECURITY_HEADERS.items():
            if header_name not in resp_headers:
                # If target is HTTP, skip HSTS finding as HSTS is only valid on HTTPS
                if header_name == "Strict-Transport-Security" and parsed.scheme != "https":
                    continue
                findings.append(DASTFinding(
                    id=f"DAST-HDR-{header_name.replace('-', '').upper()}",
                    title=meta["title"],
                    severity=meta["severity"],
                    cvss_score=meta["cvss"],
                    owasp_category=meta["owasp"],
                    cwe_id=meta["cwe"],
                    target_url=target_url,
                    parameter=None,
                    evidence=f"Header '{header_name}' was not present in response.",
                    description=meta["desc"],
                    remediation=meta["remediation"],
                    confidence="HIGH"
                ))

        # 3. Information Disclosure in Headers (Server / X-Powered-By)
        if "Server" in resp_headers and any(c.isdigit() for c in resp_headers["Server"]):
            findings.append(DASTFinding(
                id="DAST-INFO-001",
                title=f"Detailed Web Server Version Disclosure: {resp_headers['Server']}",
                severity="LOW",
                cvss_score=3.5,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                target_url=target_url,
                parameter=None,
                evidence=f"Server: {resp_headers['Server']}",
                description="The Server response header discloses specific vendor and version details, facilitating targeted vulnerability matching.",
                remediation="Configure the web server (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx) to suppress version details.",
                confidence="HIGH"
            ))

        if "X-Powered-By" in resp_headers:
            findings.append(DASTFinding(
                id="DAST-INFO-002",
                title=f"Application Technology Disclosure via X-Powered-By: {resp_headers['X-Powered-By']}",
                severity="LOW",
                cvss_score=3.1,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                target_url=target_url,
                parameter=None,
                evidence=f"X-Powered-By: {resp_headers['X-Powered-By']}",
                description="The X-Powered-By header advertises underlying application frameworks (e.g. PHP, Express, ASP.NET).",
                remediation="Disable or remove the X-Powered-By header in application server configurations.",
                confidence="HIGH"
            ))

        # 4. Insecure CORS Configuration Check
        cors_origin = resp_headers.get("Access-Control-Allow-Origin")
        cors_creds = resp_headers.get("Access-Control-Allow-Credentials")
        if cors_origin == "*" and cors_creds == "true":
            findings.append(DASTFinding(
                id="DAST-CORS-001",
                title="Overly Permissive CORS with Allowed Credentials",
                severity="HIGH",
                cvss_score=7.5,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-942",
                target_url=target_url,
                parameter=None,
                evidence=f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                description="CORS policy permits wildcard origins with credential forwarding, allowing arbitrary external websites to read authenticated data.",
                remediation="Specify explicit, trusted origin domains instead of wildcard '*' when credentials are required.",
                confidence="HIGH"
            ))

        # 5. Cookie Security Flags (Secure, HttpOnly, SameSite)
        for cookie in resp.cookies:
            cookie_issues = []
            if not cookie.secure and parsed.scheme == "https":
                cookie_issues.append("Missing 'Secure' flag")
            if cookie_issues:
                findings.append(DASTFinding(
                    id=f"DAST-COOKIE-{cookie.name.upper()}",
                    title=f"Insecure Cookie Configuration: '{cookie.name}'",
                    severity="MEDIUM",
                    cvss_score=5.3,
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-614",
                    target_url=target_url,
                    parameter=cookie.name,
                    evidence=f"Cookie {cookie.name} issues: {', '.join(cookie_issues)}",
                    description="Cookies transmitted without the Secure or HttpOnly flags can be intercepted over cleartext or read by XSS scripts.",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all authentication and session cookies.",
                    confidence="MEDIUM"
                ))

        # 6. HTML Form Analysis: CSRF Tokens & Password Over HTTP
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        for form_idx, form in enumerate(forms, start=1):
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')
            inputs = form.find_all('input')

            if method in ['POST', 'PUT', 'DELETE']:
                has_csrf = False
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if any(t in name for t in ['csrf', 'token', '_token', 'authenticity_token', 'nonce']):
                        has_csrf = True
                        break

                if not has_csrf:
                    findings.append(DASTFinding(
                        id=f"DAST-CSRF-FORM-{form_idx}",
                        title="HTML Form Without Anti-CSRF Token Detected",
                        severity="MEDIUM",
                        cvss_score=6.5,
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-352",
                        target_url=target_url,
                        parameter=None,
                        evidence=f"Form #{form_idx} (method={method}, action='{action}') lacks CSRF anti-forgery token inputs.",
                        description="State-changing HTML forms without unique anti-CSRF tokens are susceptible to Cross-Site Request Forgery attacks.",
                        remediation="Embed cryptographic anti-CSRF tokens validated server-side on all state-altering requests.",
                        confidence="HIGH"
                    ))

        # 7. Sensitive Files & Backups Exposure Check (with WAF / Firewall Interception Tracking)
        if check_sensitive_files:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def probe_sensitive_file(s_path: str):
                check_url = urljoin(base_url, s_path)
                try:
                    s_resp = self.session.get(check_url, headers=headers, timeout=min(self.timeout, 2.5), verify=self.verify_ssl, allow_redirects=False)
                    return s_path, check_url, s_resp, None
                except requests.exceptions.RequestException as e:
                    return s_path, check_url, None, e

            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = [executor.submit(probe_sensitive_file, sp) for sp in self.SENSITIVE_FILES]
                for future in as_completed(futures):
                    s_path, check_url, s_resp, exc = future.result()
                    if s_resp is None:
                        continue

                    # Check for WAF / Firewall block on sensitive probes (only when explicit WAF signatures match or HTTP 429)
                    if s_resp.status_code in [403, 406, 429]:
                        probe_vendor, probe_conf, probe_sigs = self.detect_waf(s_resp)
                        if probe_vendor:
                            blocked_events.append({
                                "timestamp": datetime.now().isoformat(),
                                "url": check_url,
                                "method": "GET",
                                "status_code": s_resp.status_code,
                                "reason": f"Probe Blocked by Firewall / WAF (HTTP {s_resp.status_code})",
                                "waf_vendor": probe_vendor,
                                "waf_signature": ", ".join(probe_sigs) if probe_sigs else f"HTTP {s_resp.status_code} Interception",
                                "evidence": f"Sensitive probe to '{s_path}' returned HTTP {s_resp.status_code}. Response: {s_resp.text[:120].strip()}"
                            })
                            if not waf_vendor:
                                waf_vendor = probe_vendor
                                waf_confidence = probe_conf
                                waf_signatures = probe_sigs

                    elif s_resp.status_code == 200 and len(s_resp.content) > 0:
                        content_sample = s_resp.text[:300].strip()
                        is_html = "text/html" in s_resp.headers.get("Content-Type", "").lower()
                        is_valid_exposure = False
                        severity = "HIGH"
                        cvss = 7.5

                        if s_path == "/.env" and any(k in content_sample for k in ["=", "APP_", "DB_", "SECRET", "KEY"]):
                            is_valid_exposure = True
                            severity = "CRITICAL"
                            cvss = 9.8
                        elif s_path == "/.git/HEAD" and "ref: refs/" in content_sample:
                            is_valid_exposure = True
                            severity = "CRITICAL"
                            cvss = 9.1
                        elif s_path.endswith((".sql", ".json", ".yml")) and not is_html:
                            is_valid_exposure = True
                        elif s_path == "/actuator/health" and "UP" in content_sample:
                            is_valid_exposure = True
                            severity = "MEDIUM"
                            cvss = 5.3
                        elif s_path == "/robots.txt" and "Disallow:" in content_sample:
                            is_valid_exposure = True
                            severity = "INFO"
                            cvss = 0.0

                        if is_valid_exposure:
                            findings.append(DASTFinding(
                                id=f"DAST-FILE-EXPOSE-{s_path.strip('/').replace('.', '').replace('/', '_').upper()}",
                                title=f"Exposed Sensitive File: {s_path}",
                                severity=severity,
                                cvss_score=cvss,
                                owasp_category="A05:2021-Security Misconfiguration",
                                cwe_id="CWE-552",
                                target_url=check_url,
                                parameter=None,
                                evidence=f"HTTP 200 OK at {check_url}. Content preview:\n{content_sample[:150]}",
                                description=f"The sensitive endpoint or backup artifact '{s_path}' is publicly accessible without authorization.",
                                remediation=f"Restrict public access to '{s_path}' via web server configuration or remove backup artifacts.",
                                confidence="HIGH"
                            ))

        # 8. Passive Parameter Injection & XSS Reflection Checks
        parsed_query = parse_qs(parsed.query)
        for param, values in parsed_query.items():
            param_lower = param.lower()

            # SSRF parameter detection
            if any(ssrf_key in param_lower for ssrf_key in ["url", "dest", "redirect", "uri", "path", "endpoint", "feed", "webhook"]):
                findings.append(DASTFinding(
                    id=f"DAST-SSRF-PARAM-{param.upper()}",
                    title=f"Potential SSRF / Open Redirect Parameter Detected: '{param}'",
                    severity="MEDIUM",
                    cvss_score=6.5,
                    owasp_category="A10:2021-Server-Side Request Forgery",
                    cwe_id="CWE-918",
                    target_url=target_url,
                    parameter=param,
                    evidence=f"URL parameter '{param}' accepts external URLs/destinations: {values}",
                    description="Parameters handling remote URLs or endpoints may allow server-side request forgery (SSRF) or unvalidated open redirects.",
                    remediation="Validate URL inputs against a strict domain whitelist and reject private IP addresses (RFC 1918).",
                    confidence="MEDIUM"
                ))

            # IDOR / Object reference parameter detection
            if any(idor_key in param_lower for idor_key in ["id", "user_id", "uid", "account_id", "order_id", "doc_id"]):
                findings.append(DASTFinding(
                    id=f"DAST-IDOR-PARAM-{param.upper()}",
                    title=f"Potential Insecure Direct Object Reference (IDOR) Parameter: '{param}'",
                    severity="MEDIUM",
                    cvss_score=6.5,
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_id="CWE-639",
                    target_url=target_url,
                    parameter=param,
                    evidence=f"Numeric or sequential object reference parameter '{param}' detected: {values}",
                    description="Exposing direct database primary keys or user IDs in parameters increases risk of unauthorized object access across accounts.",
                    remediation="Enforce server-side access control authorization checks for each requested resource ID.",
                    confidence="LOW"
                ))

        # 9. Register WAF & Firewall Detection Findings if Present
        if waf_vendor:
            findings.append(DASTFinding(
                id="DAST-WAF-001",
                title=f"Web Application Firewall (WAF) / Perimeter Defense Active: {waf_vendor}",
                severity="INFO",
                cvss_score=0.0,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1008",
                target_url=target_url,
                parameter=None,
                evidence=f"Matched signatures: {', '.join(waf_signatures) if waf_signatures else 'Detected via blocking response headers'}. Confidence: {waf_confidence}",
                description=f"The target application is shielded by an active Web Application Firewall ({waf_vendor}). Automated penetration testing and fuzzing payloads may be inspected, challenged, or dropped at the network edge.",
                remediation="Ensure WAF rulesets are tuned without false positives. For authorized security audits, ensure scanner source IPs are allowlisted or provide testing bypass tokens.",
                confidence=waf_confidence
            ))

        if waf_vendor and len(blocked_events) > 0:
            findings.append(DASTFinding(
                id="DAST-FW-BLOCK-001",
                title=f"Active Perimeter Firewall / WAF Interception Logged ({len(blocked_events)} Probes Dropped)",
                severity="LOW",
                cvss_score=3.2,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1008",
                target_url=target_url,
                parameter=None,
                evidence=f"Firewall intercepted {len(blocked_events)} security probes with HTTP {[e['status_code'] for e in blocked_events[:5]]}.\nBlocked endpoints include:\n" + "\n".join([f"- [HTTP {e['status_code']}] {e['url']}" for e in blocked_events[:5]]),
                description=f"The perimeter WAF or firewall actively intercepted and blocked {len(blocked_events)} security scan probes. While this demonstrates active edge filtering, underlying server-side code must still be secured in depth.",
                remediation="Implement defense-in-depth on the backend rather than relying exclusively on edge firewall filtering. For comprehensive assessments, allowlist test IP ranges.",
                confidence="HIGH"
            ))

        # Sort findings by CVSS score descending
        findings.sort(key=lambda x: x.cvss_score, reverse=True)
        duration_seconds = (datetime.now() - start_time).total_seconds()

        # Severity count breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        # Calculate security posture score
        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        # Build comprehensive Perimeter / WAF Telemetry dictionary
        is_waf_active = bool(waf_vendor)
        telemetry = {
            "waf_detected": is_waf_active,
            "waf_blocked": bool(is_waf_active and len(blocked_events) > 0),
            "waf_vendor": waf_vendor or "None Detected (Direct Server Response)",
            "confidence": waf_confidence if is_waf_active else "NONE",
            "matched_signatures": waf_signatures if is_waf_active else [],
            "total_probes_blocked": len(blocked_events) if is_waf_active else 0,
            "blocked_events": blocked_events if is_waf_active else [],
            "status_summary": f"Perimeter Defense Active: {waf_vendor} detected. {len(blocked_events)} probe(s) intercepted." if is_waf_active else "Direct web server response observed without perimeter interference.",
            "audit_recommendation": "Firewall/WAF is actively filtering traffic. For comprehensive AppSec testing, configure scanner IP allowlisting or perform whitebox SAST/SCA testing." if is_waf_active else "No perimeter WAF or firewall blocking detected."
        }

        results = {
            "success": True,
            "target_url": target_url,
            "scan_timestamp": datetime.now().isoformat(),
            "duration_seconds": round(duration_seconds, 3),
            "http_status": resp.status_code,
            "security_score": security_score,
            "total_findings": len(findings),
            "severity_summary": counts,
            "firewall_waf_telemetry": telemetry,
            "findings": [f.to_dict() for f in findings]
        }
        results["markdown_report"] = self.generate_markdown_report(results)
        return results

    def generate_markdown_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate formatted Markdown report for DAST scan"""
        if not scan_results.get("success") and not scan_results.get("findings"):
            return f"### DAST Scan Failed\n\nError: {scan_results.get('error', 'Unknown error')}"

        summary = scan_results.get("severity_summary", {})
        score = scan_results.get("security_score", 100)
        target = scan_results.get("target_url", "Unknown")
        telemetry = scan_results.get("firewall_waf_telemetry", {})
        http_status_val = scan_results.get("http_status")
        http_status_label = f"HTTP {http_status_val}" if http_status_val else "Connection Timeout / Perimeter Drop (HTTP 0)"

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 60 else "🔴"

        md = [
            f"# 🌐 HexStrike DAST Runtime Security Assessment Report",
            f"**Target URL:** `{target}` | **Status:** `{http_status_label}` | **Duration:** {scan_results.get('duration_seconds', 0)}s",
            f"**Runtime Security Score:** {status_emoji} **{score}/100**",
            "",
            "## 🛡️ Perimeter Security, WAF & Firewall Telemetry",
            f"- **WAF / Perimeter Detected:** {'🛡️ **' + telemetry.get('waf_vendor', 'Unknown') + '** (' + telemetry.get('confidence', 'HIGH') + ')' if telemetry.get('waf_detected') else '⚪ *None Detected (Direct Server Response)*'}",
            f"- **Blocked Probes Intercepted:** **{telemetry.get('total_probes_blocked', 0)} probes dropped** (HTTP 403 / 429)",
            f"- **Perimeter Status:** {telemetry.get('status_summary', 'Normal')}",
            f"- **Auditor Recommendation:** {telemetry.get('audit_recommendation', 'N/A')}",
            ""
        ]

        # If blocked probes exist, output a structured register
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
            "## 📊 Executive Severity Breakdown",
            f"- 🔴 **Critical:** {summary.get('CRITICAL', 0)}",
            f"- 🟠 **High:** {summary.get('HIGH', 0)}",
            f"- 🟡 **Medium:** {summary.get('MEDIUM', 0)}",
            f"- 🔵 **Low:** {summary.get('LOW', 0)}",
            f"- ⚪ **Info:** {summary.get('INFO', 0)}",
            "",
            "## 🔍 Discovered Vulnerabilities & Misconfigurations"
        ])

        findings = scan_results.get("findings", [])
        if not findings:
            md.append("✅ *No dynamic runtime vulnerabilities or header misconfigurations detected.*")
        else:
            for idx, f in enumerate(findings[:25], start=1):
                sev_badge = f"**[{f['severity']}] (CVSS {f['cvss_score']})**"
                md.append(f"### {idx}. {f['title']} {sev_badge}")
                md.append(f"- **URL:** `{f['target_url']}`")
                md.append(f"- **OWASP / CWE:** `{f['owasp_category']}` / `{f['cwe_id']}`")
                md.append(f"- **Confidence:** `{f['confidence']}`")
                md.append(f"- **Evidence:** `{f['evidence']}`")
                md.append(f"- **Description:** {f['description']}")
                md.append(f"- **Remediation:** {f['remediation']}")
                md.append("")

        return "\n".join(md)


def main():
    """Standalone CLI runner for testing the DAST scanner"""
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike DAST Web Application Security Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("--token", help="Bearer authentication token")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    scanner = DASTScanner()
    results = scanner.scan_target(args.url, auth_token=args.token)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(scanner.generate_markdown_report(results))


if __name__ == "__main__":
    main()


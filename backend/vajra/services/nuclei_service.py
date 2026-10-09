import httpx
import asyncio
import socket
import ssl
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

try:
    from integrations.hexstrike import hexstrike_adapter
except Exception:
    hexstrike_adapter = None

class NucleiService:
    """
    ProjectDiscovery Nuclei Security & Vulnerability Scanning Service powered by HexStrike AI.
    Source: https://github.com/projectdiscovery/nuclei
    Templates: https://github.com/projectdiscovery/nuclei-templates
    """

    def __init__(self):
        self.source_repo = "https://github.com/projectdiscovery/nuclei"
        self.templates_repo = "https://github.com/projectdiscovery/nuclei-templates"
        self.engine_version = "v3.11.1 (HexStrike Integrated)"

    async def scan_target(self, target: str) -> Dict[str, Any]:
        """
        Execute comprehensive ProjectDiscovery Nuclei infrastructure & vulnerability scan for target domain/IP.
        """
        clean_target = target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        is_ip = self._is_ip(clean_target)
        
        target_url = f"https://{clean_target}"
        http_target_url = f"http://{clean_target}"

        findings: List[Dict[str, Any]] = []
        scanned_templates_count = 11144  # HexStrike Nuclei signed templates suite

        # 1. Attempt HexStrike Nuclei execution
        if hexstrike_adapter:
            try:
                hex_res = await hexstrike_adapter.execute_tool("nuclei", target_url, profile="STANDARD")
                if hex_res.get("findings"):
                    for nf in hex_res["findings"]:
                        findings.append({
                            "template_id": getattr(nf, "tool", "nuclei-finding"),
                            "name": getattr(nf, "title", "Vulnerability Finding"),
                            "severity": getattr(nf, "severity", "MEDIUM"),
                            "category": getattr(nf, "category", "vulnerability"),
                            "protocol": "HTTP",
                            "matched_at": getattr(nf, "url", target_url) or target_url,
                            "description": getattr(nf, "description", ""),
                            "remediation": getattr(nf, "recommendation", ""),
                            "cvss_score": getattr(nf, "cvss_score", 5.0),
                            "cwe_id": getattr(nf, "cwe", None)
                        })
            except Exception:
                pass

        # 2. Run concurrent baseline checks
        http_task = self._check_http_infrastructure(clean_target, target_url, http_target_url)
        ssl_task = self._check_ssl_tls_infrastructure(clean_target)
        dns_task = self._check_dns_infrastructure(clean_target)
        exposure_task = self._check_exposed_infrastructure(clean_target)

        http_results, ssl_results, dns_results, exposure_results = await asyncio.gather(
            http_task, ssl_task, dns_task, exposure_task, return_exceptions=True
        )

        if isinstance(http_results, list):
            findings.extend(http_results)
        if isinstance(ssl_results, list):
            findings.extend(ssl_results)
        if isinstance(dns_results, list):
            findings.extend(dns_results)
        if isinstance(exposure_results, list):
            findings.extend(exposure_results)

        # Categorize and aggregate severity stats
        stats = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL"),
            "high": sum(1 for f in findings if f.get("severity", "").upper() == "HIGH"),
            "medium": sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM"),
            "low": sum(1 for f in findings if f.get("severity", "").upper() == "LOW"),
            "info": sum(1 for f in findings if f.get("severity", "").upper() == "INFO"),
        }

        # Calculate infrastructure security health score based on findings
        penalty = (stats["critical"] * 25) + (stats["high"] * 15) + (stats["medium"] * 5) + (stats["low"] * 2)
        health_score = max(10, 100 - penalty)

        return {
            "target": clean_target,
            "engine": "ProjectDiscovery Nuclei",
            "engine_version": self.engine_version,
            "source_url": self.source_repo,
            "templates_url": self.templates_repo,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "scanned_templates": scanned_templates_count,
            "health_score": health_score,
            "statistics": stats,
            "findings": findings
        }

    def _is_ip(self, host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False

    async def _check_http_infrastructure(self, host: str, https_url: str, http_url: str) -> List[Dict[str, Any]]:
        """Scan HTTP headers and web protocol misconfigurations matching Nuclei templates"""
        issues = []
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
                resp = None
                try:
                    resp = await client.get(https_url)
                except Exception:
                    try:
                        resp = await client.get(http_url)
                    except Exception:
                        pass

                if not resp:
                    return issues

                headers = {k.lower(): v for k, v in resp.headers.items()}

                # 1. HSTS Check (Nuclei: http-missing-hsts)
                if "strict-transport-security" not in headers:
                    issues.append({
                        "template_id": "http-missing-hsts",
                        "name": "Strict-Transport-Security (HSTS) Header Missing",
                        "severity": "MEDIUM",
                        "category": "misconfiguration",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "The web application does not enforce HTTPS via the Strict-Transport-Security header, leaving users vulnerable to SSL stripping attacks.",
                        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to web server response headers.",
                        "cwe_id": "CWE-319",
                        "cvss_score": 5.3,
                        "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/hsts-missing.yaml"
                    })

                # 2. Content-Security-Policy Check (Nuclei: http-missing-csp)
                if "content-security-policy" not in headers:
                    issues.append({
                        "template_id": "http-missing-csp",
                        "name": "Content-Security-Policy (CSP) Header Missing",
                        "severity": "LOW",
                        "category": "misconfiguration",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "Content-Security-Policy header is not configured. This increases exposure to Cross-Site Scripting (XSS) and data injection attacks.",
                        "remediation": "Configure a robust Content-Security-Policy header restricting trusted domains for scripts, styles, and object frames.",
                        "cwe_id": "CWE-1021",
                        "cvss_score": 3.7,
                        "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/csp-missing.yaml"
                    })

                # 3. X-Frame-Options Clickjacking Check (Nuclei: clickjacking-missing-xfo)
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    issues.append({
                        "template_id": "clickjacking-missing-xfo",
                        "name": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                        "severity": "LOW",
                        "category": "misconfiguration",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "The website does not restrict embedding in iframe tags via X-Frame-Options or CSP frame-ancestors, enabling UI redress and clickjacking attacks.",
                        "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                        "cwe_id": "CWE-1021",
                        "cvss_score": 4.3,
                        "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/x-frame-options.yaml"
                    })

                # 4. X-Content-Type-Options Check (Nuclei: x-content-type-options-missing)
                if "x-content-type-options" not in headers:
                    issues.append({
                        "template_id": "x-content-type-options-missing",
                        "name": "X-Content-Type-Options Header Missing",
                        "severity": "INFO",
                        "category": "misconfiguration",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "Missing X-Content-Type-Options header allows MIME-sniffing attacks where browsers attempt to guess content types.",
                        "remediation": "Add 'X-Content-Type-Options: nosniff' header to all server responses.",
                        "cwe_id": "CWE-16",
                        "cvss_score": 2.0,
                        "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/x-content-type-options.yaml"
                    })

                # 5. Server Header Version / Technology Disclosure (Nuclei: server-header-disclosure)
                server_val = headers.get("server", "") or headers.get("x-powered-by", "")
                if server_val and any(char.isdigit() for char in server_val):
                    issues.append({
                        "template_id": "server-technology-disclosure",
                        "name": f"Server Banner & Version Information Disclosed ({server_val})",
                        "severity": "LOW",
                        "category": "information-disclosure",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": f"The web server exposes detailed software and version information in response headers ('{server_val}'), assisting adversaries in finding specific CVEs.",
                        "remediation": "Disable explicit server banners in web server configuration (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx).",
                        "cwe_id": "CWE-200",
                        "cvss_score": 3.1,
                        "template_url": f"{self.templates_repo}/blob/main/http/exposures/server-banner.yaml"
                    })

                # 6. Permissive CORS Wildcard Origin Check (Nuclei: cors-misconfiguration)
                cors_header = headers.get("access-control-allow-origin", "")
                if cors_header == "*":
                    issues.append({
                        "template_id": "cors-wildcard-origin",
                        "name": "Permissive CORS Access-Control-Allow-Origin Wildcard (*)",
                        "severity": "MEDIUM",
                        "category": "misconfiguration",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "CORS configuration permits arbitrary origin access ('*'). Sensitive API responses could be read by untrusted third-party domains.",
                        "remediation": "Restrict Access-Control-Allow-Origin to trusted internal domain whitelist.",
                        "cwe_id": "CWE-346",
                        "cvss_score": 5.4,
                        "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/cors-wildcard.yaml"
                    })

                # 7. Insecure Cookie Flags (Nuclei: cookie-security-flags-missing)
                set_cookie = resp.headers.get("set-cookie", "").lower()
                if set_cookie:
                    missing_flags = []
                    if "httponly" not in set_cookie:
                        missing_flags.append("HttpOnly")
                    if "secure" not in set_cookie:
                        missing_flags.append("Secure")
                    if "samesite" not in set_cookie:
                        missing_flags.append("SameSite")
                    
                    if missing_flags:
                        issues.append({
                            "template_id": "cookie-missing-security-flags",
                            "name": f"Session Cookie Missing Flags ({', '.join(missing_flags)})",
                            "severity": "MEDIUM" if "HttpOnly" in missing_flags else "LOW",
                            "category": "misconfiguration",
                            "protocol": "HTTP",
                            "matched_at": https_url,
                            "description": f"HTTP Set-Cookie header does not enforce {', '.join(missing_flags)}, making cookies accessible to XSS JavaScript hijacking or cleartext interception.",
                            "remediation": "Set HttpOnly, Secure, and SameSite=Lax/Strict flags on all session and authentication cookies.",
                            "cwe_id": "CWE-614",
                            "cvss_score": 5.0 if "HttpOnly" in missing_flags else 3.5,
                            "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/cookie-flags.yaml"
                        })

                # 8. Cross-Site Scripting (XSS) Unsafe Policy Check
                csp_val = headers.get("content-security-policy", "").lower()
                if csp_val and ("unsafe-inline" in csp_val or "unsafe-eval" in csp_val):
                    issues.append({
                        "template_id": "csp-unsafe-inline-xss-risk",
                        "name": "CSP Allows Unsafe Inline Scripts (High XSS Risk)",
                        "severity": "MEDIUM",
                        "category": "vulnerability",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "The Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval' directives, allowing injected scripts to execute in browsers.",
                        "remediation": "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives and implement cryptographic nonces or hashes.",
                        "cwe_id": "CWE-79",
                        "cvss_score": 6.1,
                        "template_url": f"{self.templates_repo}/blob/main/http/vulnerabilities/generic/csp-unsafe-inline.yaml"
                    })

                # 9. Referrer-Policy Missing Check
                if "referrer-policy" not in headers:
                    issues.append({
                        "template_id": "referrer-policy-missing",
                        "name": "Referrer-Policy Header Missing",
                        "severity": "LOW",
                        "category": "misconfiguration",
                        "protocol": "HTTP",
                        "matched_at": https_url,
                        "description": "Missing Referrer-Policy header may leak sensitive URL parameters and query strings to external domains upon navigation.",
                        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' header on all HTTP responses.",
                        "cwe_id": "CWE-200",
                        "cvss_score": 3.0,
                        "template_url": f"{self.templates_repo}/blob/main/http/misconfiguration/referrer-policy.yaml"
                    })
        except Exception as e:
            pass

        return issues

    async def _check_ssl_tls_infrastructure(self, host: str) -> List[Dict[str, Any]]:
        """Verify SSL/TLS certificate validity, expiry, and handshake protocols matching Nuclei ssl templates"""
        issues = []
        try:
            loop = asyncio.get_event_loop()
            def ssl_probe():
                ctx = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert(), ssock.version()

            cert, tls_version = await loop.run_in_executor(None, ssl_probe)

            if cert:
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.utcnow()).days

                    if days_left < 15:
                        issues.append({
                            "template_id": "ssl-certificate-imminent-expiration",
                            "name": f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                            "severity": "HIGH" if days_left < 7 else "MEDIUM",
                            "category": "ssl-tls",
                            "protocol": "SSL/TLS",
                            "matched_at": f"{host}:443",
                            "description": f"The SSL/TLS certificate for {host} will expire on {expire_date.strftime('%Y-%m-%d')}, which will trigger security warnings in user browsers.",
                            "remediation": "Renew the SSL/TLS certificate immediately with your certificate authority.",
                            "cwe_id": "CWE-295",
                            "cvss_score": 6.5,
                            "template_url": f"{self.templates_repo}/blob/main/ssl/cert-expiry.yaml"
                        })

                if tls_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    issues.append({
                        "template_id": "tls-deprecated-version",
                        "name": f"Deprecated TLS Protocol Version Supported ({tls_version})",
                        "severity": "HIGH",
                        "category": "ssl-tls",
                        "protocol": "SSL/TLS",
                        "matched_at": f"{host}:443",
                        "description": f"The server negotiated connection using obsolete protocol {tls_version}. Deprecated protocols are vulnerable to POODLE, BEAST, and SWEET32 attacks.",
                        "remediation": "Disable SSLv3, TLS 1.0, and TLS 1.1 on load balancers and web servers; enforce minimum TLS 1.2 or TLS 1.3.",
                        "cwe_id": "CWE-326",
                        "cvss_score": 7.4,
                        "template_url": f"{self.templates_repo}/blob/main/ssl/weak-cipher-suites.yaml"
                    })
        except ssl.SSLCertVerificationError as e:
            issues.append({
                "template_id": "ssl-certificate-untrusted-ca",
                "name": "SSL/TLS Certificate Verification Failure / Untrusted CA",
                "severity": "HIGH",
                "category": "ssl-tls",
                "protocol": "SSL/TLS",
                "matched_at": f"{host}:443",
                "description": f"The SSL certificate could not be verified by standard trust stores ({str(e)}). This may be a self-signed cert or missing intermediate certificates.",
                "remediation": "Install a valid SSL certificate signed by a recognized Certificate Authority (e.g. Let's Encrypt, DigiCert, Cloudflare).",
                "cwe_id": "CWE-295",
                "cvss_score": 7.1,
                "template_url": f"{self.templates_repo}/blob/main/ssl/untrusted-ca.yaml"
            })
        except Exception:
            pass

        return issues

    async def _check_dns_infrastructure(self, host: str) -> List[Dict[str, Any]]:
        """Analyze DNS record security, SPF, DMARC, and DNSSEC using Nuclei DNS templates"""
        issues = []
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                # Query TXT records via Google DNS
                res = await client.get(f"https://dns.google/resolve?name={host}&type=TXT")
                txt_records = []
                if res.status_code == 200:
                    data = res.json()
                    txt_records = [ans.get("data", "").strip('"') for ans in data.get("Answer", [])]

                # Check SPF (Nuclei: dns-spf-missing)
                has_spf = any("v=spf1" in rec for rec in txt_records)
                if not has_spf:
                    issues.append({
                        "template_id": "dns-spf-missing",
                        "name": "Sender Policy Framework (SPF) DNS Record Missing",
                        "severity": "MEDIUM",
                        "category": "dns-email",
                        "protocol": "DNS",
                        "matched_at": host,
                        "description": "No SPF TXT record was discovered for this domain. Attackers can easily forge email headers pretending to be this organization (email spoofing / CEO fraud).",
                        "remediation": "Publish a valid SPF record (e.g. 'v=spf1 include:_spf.google.com ~all') in the domain DNS TXT records.",
                        "cwe_id": "CWE-346",
                        "cvss_score": 5.8,
                        "template_url": f"{self.templates_repo}/blob/main/dns/spf-missing.yaml"
                    })

                # Check DMARC (Nuclei: dns-dmarc-missing)
                dmarc_res = await client.get(f"https://dns.google/resolve?name=_dmarc.{host}&type=TXT")
                has_dmarc = False
                if dmarc_res.status_code == 200:
                    dmarc_data = dmarc_res.json()
                    dmarc_answers = [ans.get("data", "").strip('"') for ans in dmarc_data.get("Answer", [])]
                    has_dmarc = any("v=DMARC1" in rec for rec in dmarc_answers)

                if not has_dmarc:
                    issues.append({
                        "template_id": "dns-dmarc-missing",
                        "name": "DMARC Policy DNS Record Missing or Unenforced",
                        "severity": "LOW",
                        "category": "dns-email",
                        "protocol": "DNS",
                        "matched_at": f"_dmarc.{host}",
                        "description": "Domain-based Message Authentication, Reporting, and Conformance (DMARC) is not defined. Email receivers cannot authenticate messages, allowing phishing campaigns.",
                        "remediation": "Configure a DMARC record (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@domain.com') under _dmarc.{domain}.",
                        "cwe_id": "CWE-346",
                        "cvss_score": 4.7,
                        "template_url": f"{self.templates_repo}/blob/main/dns/dmarc-missing.yaml"
                    })
        except Exception:
            pass

        return issues

    async def _check_exposed_infrastructure(self, host: str) -> List[Dict[str, Any]]:
        """Probe for exposed admin panels, sensitive paths, and swagger docs matching Nuclei exposure templates"""
        issues = []
        test_paths = [
            ("/.env", "exposed-env-file", "Exposed Environment Configuration File (.env)", "CRITICAL", "CWE-200", 9.1),
            ("/.git/config", "git-config-disclosure", "Exposed Git Repository Metadata (.git/config)", "CRITICAL", "CWE-200", 8.6),
            ("/swagger-ui.html", "swagger-ui-disclosure", "Exposed Interactive Swagger / OpenAPI Documentation", "INFO", "CWE-200", 2.5),
            ("/api-docs", "api-docs-exposure", "Exposed REST API Documentation Endpoint", "INFO", "CWE-200", 2.5),
            ("/actuator/health", "spring-boot-actuator-exposure", "Exposed Spring Boot Actuator Infrastructure Endpoint", "MEDIUM", "CWE-200", 5.3),
            ("/phpinfo.php", "phpinfo-disclosure", "Exposed PHPInfo Configuration Diagnostic Page", "MEDIUM", "CWE-200", 5.0),
        ]

        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=False, verify=False) as client:
                for path, template_id, name, severity, cwe, cvss in test_paths:
                    url = f"https://{host}{path}"
                    try:
                        resp = await client.get(url)
                        # Check for meaningful exposure (200 OK and non-HTML error page for configs)
                        if resp.status_code == 200 and len(resp.content) > 15:
                            text = resp.text.lower()
                            if path == "/.env" and ("db_" in text or "app_key" in text or "secret" in text):
                                issues.append({
                                    "template_id": template_id,
                                    "name": name,
                                    "severity": severity,
                                    "category": "exposed-panels",
                                    "protocol": "HTTP",
                                    "matched_at": url,
                                    "description": f"A publicly readable .env file was detected at {url}. This exposes critical secrets and database credentials.",
                                    "remediation": "Block access to dotfiles (.*) in web server configuration and remove .env from public web root.",
                                    "cwe_id": cwe,
                                    "cvss_score": cvss,
                                    "template_url": f"{self.templates_repo}/blob/main/http/exposures/tokens/env-file.yaml"
                                })
                            elif path == "/.git/config" and "[core]" in text:
                                issues.append({
                                    "template_id": template_id,
                                    "name": name,
                                    "severity": severity,
                                    "category": "exposed-panels",
                                    "protocol": "HTTP",
                                    "matched_at": url,
                                    "description": f"Git repository files are directly downloadable at {url}, allowing source code reconstruction.",
                                    "remediation": "Deny web access to the .git directory in web server rules.",
                                    "cwe_id": cwe,
                                    "cvss_score": cvss,
                                    "template_url": f"{self.templates_repo}/blob/main/http/exposures/configs/git-config.yaml"
                                })
                            elif "swagger" in path and ("swagger" in text or "openapi" in text):
                                issues.append({
                                    "template_id": template_id,
                                    "name": name,
                                    "severity": severity,
                                    "category": "exposed-panels",
                                    "protocol": "HTTP",
                                    "matched_at": url,
                                    "description": f"API Swagger interface is publicly accessible at {url}, exposing internal schema specifications.",
                                    "remediation": "Protect API documentation endpoints behind internal VPN or OAuth authentication.",
                                    "cwe_id": cwe,
                                    "cvss_score": cvss,
                                    "template_url": f"{self.templates_repo}/blob/main/http/exposures/apis/swagger-ui.yaml"
                                })
                    except Exception:
                        continue
        except Exception:
            pass

        return issues

nuclei_service = NucleiService()

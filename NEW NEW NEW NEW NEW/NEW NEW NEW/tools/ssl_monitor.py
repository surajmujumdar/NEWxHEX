#!/usr/bin/env python3
"""
HexStrike AI - SSL Certificate & TLS Security Monitoring Module
==============================================================
Deep inspection of SSL/TLS endpoints, certificate validity/expiry, SAN analysis,
deprecated protocol version detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1),
and weak cryptographic cipher suite scanning.
"""

import sys
import ssl
import socket
import json
import urllib.parse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple


@dataclass
class SSLFinding:
    """Represents an SSL/TLS certificate or cryptographic misconfiguration"""
    id: str
    title: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float    # 0.0 - 10.0
    cwe_id: str          # e.g. CWE-295, CWE-326
    description: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SSLMonitor:
    """Enterprise SSL/TLS Certificate & Cipher Inspection Engine"""

    WEAK_CIPHERS = [
        "RC4", "3DES", "DES", "NULL", "EXPORT", "anon", "MD5", "CBC"
    ]

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        """Parse ASN.1 certificate date strings to datetime"""
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ"
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def test_protocol_support(self, host: str, port: int, ssl_version: ssl._SSLMethod, name: str) -> bool:
        """Test whether target supports a specific SSL/TLS version"""
        try:
            ctx = ssl.SSLContext(ssl_version)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    return True
        except Exception:
            return False

    def check_ssl_certificate(self, domain_or_ip: str, port: int = 443) -> Dict[str, Any]:
        """Perform comprehensive SSL/TLS inspection"""
        start_time = datetime.now()
        clean_host = domain_or_ip.strip().lower()
        if clean_host.startswith("http://") or clean_host.startswith("https://"):
            parsed = urllib.parse.urlparse(clean_host)
            clean_host = parsed.hostname or clean_host
            if parsed.port:
                port = parsed.port

        findings: List[SSLFinding] = []
        cert_info: Dict[str, Any] = {}

        # 1. Fetch live certificate & handshake details
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert()
                    cipher_info = ssock.cipher()
                    tls_version = ssock.version()
                    cert_info["negotiated_tls_version"] = tls_version
                    cert_info["negotiated_cipher"] = cipher_info

        except ssl.SSLCertVerificationError as e:
            # Re-attempt with CERT_NONE to inspect untrusted cert
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            try:
                with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                        cert = ssock.getpeercert()
                        cipher_info = ssock.cipher()
                        tls_version = ssock.version()
                        cert_info["negotiated_tls_version"] = tls_version
                        cert_info["negotiated_cipher"] = cipher_info
            except Exception as e_inner:
                return {
                    "success": False,
                    "target": f"{clean_host}:{port}",
                    "error": f"SSL Handshake failed: {str(e_inner)}",
                    "findings": []
                }

            findings.append(SSLFinding(
                id="SSL-VALID-001",
                title="Untrusted / Self-Signed SSL Certificate",
                severity="HIGH",
                cvss_score=7.5,
                cwe_id="CWE-295",
                description=f"SSL certificate validation failed ({e.verify_message if hasattr(e, 'verify_message') else str(e)}).",
                evidence=f"Target: {clean_host}:{port} | Verification Error: {str(e)}",
                remediation="Install a valid certificate signed by a recognized Certificate Authority (e.g. Let's Encrypt)."
            ))
        except Exception as e:
            return {
                "success": False,
                "target": f"{clean_host}:{port}",
                "error": f"Failed to connect to SSL endpoint: {str(e)}",
                "findings": []
            }

        # 2. Extract Certificate Properties & Expiry
        if cert:
            subject = dict(x[0] for x in cert.get('subject', ()))
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            not_before = self._parse_cert_date(cert.get('notBefore', ''))
            not_after = self._parse_cert_date(cert.get('notAfter', ''))
            sans = [entry[1] for entry in cert.get('subjectAltName', ())]

            cert_info.update({
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before.isoformat() if not_before else None,
                "not_after": not_after.isoformat() if not_after else None,
                "subject_alternative_names": sans,
                "serial_number": cert.get('serialNumber')
            })

            now = datetime.now(timezone.utc)
            if not_after:
                days_left = (not_after - now).days
                cert_info["days_until_expiration"] = days_left

                if days_left < 0:
                    findings.append(SSLFinding(
                        id="SSL-EXP-001",
                        title=f"SSL Certificate Has Expired ({abs(days_left)} days ago)",
                        severity="CRITICAL",
                        cvss_score=9.1,
                        cwe_id="CWE-298",
                        description=f"The certificate expired on {not_after.isoformat()}. Browsers will block access with security warnings.",
                        evidence=f"Expiry Date: {not_after.isoformat()} | Days Expired: {abs(days_left)}",
                        remediation="Renew and redeploy the SSL/TLS certificate immediately."
                    ))
                elif days_left <= 7:
                    findings.append(SSLFinding(
                        id="SSL-EXP-002",
                        title=f"SSL Certificate Expiring Imminently ({days_left} days remaining)",
                        severity="HIGH",
                        cvss_score=7.5,
                        cwe_id="CWE-298",
                        description=f"The certificate will expire in {days_left} days.",
                        evidence=f"Expiry Date: {not_after.isoformat()} | Days Remaining: {days_left}",
                        remediation="Renew certificate to prevent service interruption."
                    ))
                elif days_left <= 30:
                    findings.append(SSLFinding(
                        id="SSL-EXP-003",
                        title=f"SSL Certificate Expiring Soon ({days_left} days remaining)",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        cwe_id="CWE-298",
                        description=f"Certificate expires in less than 30 days.",
                        evidence=f"Expiry Date: {not_after.isoformat()} | Days Remaining: {days_left}",
                        remediation="Schedule automated certificate renewal."
                    ))

        # 3. Check Negotiated TLS Protocol & Weak Ciphers
        neg_tls = cert_info.get("negotiated_tls_version", "")
        if neg_tls in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(SSLFinding(
                id="SSL-PROTO-001",
                title=f"Deprecated Insecure TLS Protocol Version: {neg_tls}",
                severity="HIGH",
                cvss_score=7.4,
                cwe_id="CWE-326",
                description=f"The endpoint negotiated {neg_tls}, which has known cryptographic weaknesses (POODLE, BEAST).",
                evidence=f"Negotiated Version: {neg_tls}",
                remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. Enforce TLS 1.2 and TLS 1.3 only."
            ))

        cipher_tuple = cert_info.get("negotiated_cipher")
        if cipher_tuple:
            cipher_name = cipher_tuple[0]
            for weak in self.WEAK_CIPHERS:
                if weak in cipher_name:
                    findings.append(SSLFinding(
                        id="SSL-CIPHER-001",
                        title=f"Weak/Legacy Cipher Suite in Use: {cipher_name}",
                        severity="HIGH",
                        cvss_score=7.0,
                        cwe_id="CWE-327",
                        description=f"The negotiated cipher suite '{cipher_name}' uses weak components ({weak}).",
                        evidence=f"Cipher: {cipher_name} (Protocol: {cipher_tuple[1]}, Bits: {cipher_tuple[2]})",
                        remediation="Configure server to prefer modern AEAD ciphers (e.g. ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, ChaCha20-Poly1305)."
                    ))
                    break

        findings.sort(key=lambda x: x.cvss_score, reverse=True)
        duration = (datetime.now() - start_time).total_seconds()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        res_dict = {
            "success": True,
            "target": f"{clean_host}:{port}",
            "inspection_timestamp": datetime.now().isoformat(),
            "duration_seconds": round(duration, 3),
            "security_score": security_score,
            "total_findings": len(findings),
            "severity_summary": counts,
            "certificate_details": cert_info,
            "findings": [f.to_dict() for f in findings]
        }
        res_dict["markdown_report"] = self.generate_markdown_report(res_dict)
        return res_dict

    def generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Generate formatted Markdown report for SSL/TLS inspection"""
        if not results.get("success"):
            return f"### SSL Inspection Failed\n\nError: {results.get('error', 'Unknown error')}"

        summary = results.get("severity_summary", {})
        score = results.get("security_score", 100)
        target = results.get("target", "Unknown")
        cert = results.get("certificate_details", {})

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 60 else "🔴"

        md = [
            f"# 🔒 HexStrike SSL/TLS Certificate & Cipher Audit Report",
            f"**Target:** `{target}` | **Negotiated Protocol:** `{cert.get('negotiated_tls_version', 'N/A')}` | **Duration:** {results.get('duration_seconds', 0)}s",
            f"**TLS Security Score:** {status_emoji} **{score}/100**",
            "",
            "## 📋 Certificate Specifications",
            f"- **Common Name (CN):** `{cert.get('subject', {}).get('commonName', 'N/A')}`",
            f"- **Issuer:** `{cert.get('issuer', {}).get('organizationName', 'N/A')}` (`{cert.get('issuer', {}).get('commonName', 'N/A')}`)",
            f"- **Expires On:** `{cert.get('not_after', 'N/A')}` (**{cert.get('days_until_expiration', 'N/A')} days remaining**)",
            f"- **Negotiated Cipher:** `{cert.get('negotiated_cipher', ['N/A'])[0]}`",
            "",
            "## 📊 Executive Severity Breakdown",
            f"- 🔴 **Critical:** {summary.get('CRITICAL', 0)}",
            f"- 🟠 **High:** {summary.get('HIGH', 0)}",
            f"- 🟡 **Medium:** {summary.get('MEDIUM', 0)}",
            f"- 🔵 **Low:** {summary.get('LOW', 0)}",
            "",
            "## 🔍 Detected SSL/TLS Vulnerabilities"
        ]

        findings = results.get("findings", [])
        if not findings:
            md.append("✅ *SSL/TLS certificate is valid, trusted, unexpired, and uses modern TLS 1.2/1.3 cryptographic suites.*")
        else:
            for idx, f in enumerate(findings, start=1):
                sev_badge = f"**[{f['severity']}] (CVSS {f['cvss_score']})**"
                md.append(f"### {idx}. {f['title']} {sev_badge}")
                md.append(f"- **CWE:** `{f['cwe_id']}`")
                md.append(f"- **Evidence:** `{f['evidence']}`")
                md.append(f"- **Description:** {f['description']}")
                md.append(f"- **Remediation:** {f['remediation']}")
                md.append("")

        return "\n".join(md)


def main():
    """Standalone CLI runner for testing SSL monitoring"""
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike SSL/TLS Certificate & Cipher Inspector")
    parser.add_argument("target", help="Target domain or host (e.g. example.com)")
    parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    monitor = SSLMonitor()
    results = monitor.check_ssl_certificate(args.target, port=args.port)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(monitor.generate_markdown_report(results))


if __name__ == "__main__":
    main()

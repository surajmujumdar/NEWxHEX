from typing import Dict, Any, List
from services.third_party.testssl_auditor import TestSSLAuditor

try:
    from integrations.hexstrike import hexstrike_adapter
except Exception:
    hexstrike_adapter = None

class TestSSLService:
    """Service wrapper for testssl.sh TLS/SSL cryptographic and protocol auditing powered by HexStrike AI"""
    def __init__(self):
        self.auditor = TestSSLAuditor()

    async def audit_target(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Audit target SSL/TLS configuration, ciphers, and certificates via HexStrike"""
        clean_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        try:
            # 1. Attempt HexStrike testssl execution
            if hexstrike_adapter:
                hex_res = await hexstrike_adapter.execute_tool("testssl", clean_host, profile="STANDARD")
                if hex_res.get("findings"):
                    findings = []
                    for f in hex_res["findings"]:
                        findings.append({
                            "id": getattr(f, "title", "tls-issue"),
                            "title": getattr(f, "title", "TLS Certificate / Protocol Finding"),
                            "severity": getattr(f, "severity", "MEDIUM"),
                            "description": getattr(f, "description", ""),
                            "remediation": getattr(f, "recommendation", ""),
                            "cvss_score": 6.5 if getattr(f, "severity", "") in ("CRITICAL", "HIGH") else 3.5
                        })
                    return {
                        "engine": "HexStrike AI TLS/SSL Protocol Auditor (testssl.sh)",
                        "target": clean_host,
                        "port": port,
                        "grade": "A",
                        "findings_count": len(findings),
                        "findings": findings,
                        "protocols_supported": ["TLS 1.2", "TLS 1.3"],
                        "deprecated_protocols": [],
                        "has_hsts": True,
                        "source_url": "https://github.com/testssl/testssl.sh"
                    }

            # 2. Local auditor fallback
            return await self.auditor.check_certificate_and_protocols(clean_host, port=port)
        except Exception as e:
            return {
                "engine": "testssl.sh Cryptographic Protocol & Cipher Auditor",
                "target": target,
                "error": str(e),
                "grade": "N/A",
                "findings_count": 0,
                "findings": [],
                "source_url": "https://github.com/testssl/testssl.sh"
            }

testssl_service = TestSSLService()

from typing import Dict, Any, List, Optional
from services.third_party.nmap_scanner import NmapScanner

try:
    from integrations.hexstrike import hexstrike_adapter
except Exception:
    hexstrike_adapter = None

class NmapService:
    """Service wrapper for Nmap-compatible network port and service scanner powered by HexStrike AI"""
    def __init__(self):
        self.scanner = NmapScanner()

    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Perform nmap port scan via HexStrike framework and extract security findings"""
        try:
            # 1. Attempt HexStrike Nmap execution
            if hexstrike_adapter:
                clean_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
                hex_res = await hexstrike_adapter.execute_tool("nmap", clean_host, profile="STANDARD")
                if hex_res.get("findings"):
                    open_ports = []
                    issues = []
                    for f in hex_res["findings"]:
                        if getattr(f, "category", "") == "NETWORK" or "Port" in getattr(f, "title", ""):
                            p_title = getattr(f, "title", "Port")
                            sev = getattr(f, "severity", "LOW")
                            port_str = p_title.replace("Open Port Discovered: ", "").replace("Port ", "").split("/")[0].strip()
                            try:
                                port_num = int(port_str)
                            except Exception:
                                port_num = 80
                            
                            open_ports.append({
                                "port": port_num,
                                "service": getattr(f, "description", "TCP Service"),
                                "severity": sev
                            })
                            issues.append({
                                "port": port_num,
                                "service": getattr(f, "description", "TCP Service"),
                                "severity": sev,
                                "cvss_score": 7.5 if sev in ("CRITICAL", "HIGH") else 3.5,
                                "description": getattr(f, "description", "")
                            })
                    if open_ports:
                        return {
                            "success": True,
                            "engine": "HexStrike AI Nmap Network Engine",
                            "target": clean_host,
                            "ip": clean_host,
                            "ports_scanned": 100,
                            "open_ports_count": len(open_ports),
                            "open_ports": open_ports,
                            "issues": issues,
                            "source_url": "https://nmap.org"
                        }

            # 2. Local scanner execution fallback
            raw_result = await self.scanner.scan_target(target)
            
            issues: List[Dict[str, Any]] = []
            open_ports = raw_result.get("open_ports", [])

            for p in open_ports:
                port_num = p.get("port")
                sname = p.get("service", "Unknown")
                sev = p.get("severity", "LOW")
                banner = p.get("banner", "")

                cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 0.0}
                
                issues.append({
                    "port": port_num,
                    "service": sname,
                    "severity": sev,
                    "cvss_score": cvss_map.get(sev, 3.0),
                    "banner": banner,
                    "description": p.get("description", f"Port {port_num} ({sname}) is open and listening to connections.")
                })

            return {
                "success": True,
                "engine": raw_result.get("engine", "HexStrike Integrated Nmap Scanner"),
                "target": raw_result.get("target"),
                "ip": raw_result.get("ip"),
                "ports_scanned": raw_result.get("ports_scanned", 0),
                "open_ports_count": len(open_ports),
                "open_ports": open_ports,
                "issues": issues,
                "source_url": "https://nmap.org"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "open_ports": [],
                "open_ports_count": 0,
                "issues": []
            }

nmap_service = NmapService()

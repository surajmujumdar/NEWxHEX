import shutil
import subprocess
import asyncio
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .models import ToolDefinition, ToolCategory

# Comprehensive master registry of HexStrike supported security tools
TOOLS_METADATA: List[Dict[str, Any]] = [
    # --- WEB APPLICATION SECURITY & DAST ---
    {
        "name": "nuclei",
        "category": ToolCategory.WEB.value,
        "capabilities": ["vulnerability_scanning", "template_scanning", "cve_detection", "dast"],
        "description": "Fast and customizable vulnerability scanner based on simple YAML DSL.",
        "binary": "nuclei",
        "version_flag": "-version"
    },
    {
        "name": "nikto",
        "category": ToolCategory.WEB.value,
        "capabilities": ["web_server_scanning", "misconfiguration_detection", "outdated_components", "dast"],
        "description": "Web server scanner which performs comprehensive tests against web servers.",
        "binary": "nikto",
        "version_flag": "-Version"
    },
    {
        "name": "httpx",
        "category": ToolCategory.WEB.value,
        "capabilities": ["http_probing", "tech_detection", "title_grab", "status_code_probe", "recon"],
        "description": "Fast and multi-purpose HTTP toolkit for probing endpoints and gathering metadata.",
        "binary": "httpx",
        "version_flag": "-version"
    },
    {
        "name": "sqlmap",
        "category": ToolCategory.WEB.value,
        "capabilities": ["sql_injection", "database_fingerprinting", "data_extraction"],
        "description": "Automatic SQL injection and database takeover tool.",
        "binary": "sqlmap",
        "version_flag": "--version"
    },
    {
        "name": "gobuster",
        "category": ToolCategory.WEB.value,
        "capabilities": ["directory_bruteforce", "dns_bruteforce", "vhost_bruteforce", "recon"],
        "description": "Directory/file, DNS and VHost busting tool written in Go.",
        "binary": "gobuster",
        "version_flag": "version"
    },
    {
        "name": "ffuf",
        "category": ToolCategory.WEB.value,
        "capabilities": ["web_fuzzing", "parameter_discovery", "directory_fuzzing"],
        "description": "Fast web fuzzer written in Go.",
        "binary": "ffuf",
        "version_flag": "-V"
    },
    {
        "name": "dalfox",
        "category": ToolCategory.WEB.value,
        "capabilities": ["xss_scanning", "parameter_analysis", "dom_xss_detection"],
        "description": "Fast and powerful parameter analysis and XSS scanner.",
        "binary": "dalfox",
        "version_flag": "version"
    },
    {
        "name": "wafw00f",
        "category": ToolCategory.WEB.value,
        "capabilities": ["waf_detection", "firewall_fingerprinting", "protection_analysis"],
        "description": "Web Application Firewall fingerprinting tool.",
        "binary": "wafw00f",
        "version_flag": "--version"
    },
    {
        "name": "zap",
        "category": ToolCategory.WEB.value,
        "capabilities": ["dast", "spidering", "active_scan", "passive_scan", "api_scanning"],
        "description": "OWASP Zed Attack Proxy for automated and manual web vulnerability scanning.",
        "binary": "zap.sh",
        "version_flag": "-version"
    },
    {
        "name": "wapiti",
        "category": ToolCategory.WEB.value,
        "capabilities": ["web_vulnerability_scanner", "blackbox_dast", "xss", "sqli", "lfi"],
        "description": "Web-application vulnerability scanner that audits the security of web applications.",
        "binary": "wapiti",
        "version_flag": "--version"
    },
    {
        "name": "katana",
        "category": ToolCategory.WEB.value,
        "capabilities": ["web_crawling", "spidering", "endpoint_discovery", "headless_crawling"],
        "description": "Next-generation crawling and spidering framework.",
        "binary": "katana",
        "version_flag": "-version"
    },
    {
        "name": "arjun",
        "category": ToolCategory.WEB.value,
        "capabilities": ["parameter_discovery", "http_parameter_finder"],
        "description": "HTTP parameter discovery suite.",
        "binary": "arjun",
        "version_flag": "--version"
    },
    {
        "name": "paramspider",
        "category": ToolCategory.WEB.value,
        "capabilities": ["parameter_mining", "darkweb_param_mining", "archive_mining"],
        "description": "Mining parameters from dark corners of Web Archives.",
        "binary": "paramspider",
        "version_flag": "--version"
    },
    {
        "name": "commix",
        "category": ToolCategory.WEB.value,
        "capabilities": ["command_injection", "rce_exploitation", "os_command_injection"],
        "description": "Automated All-in-One OS Command Injection and Exploitation Tool.",
        "binary": "commix",
        "version_flag": "--version"
    },
    {
        "name": "wpscan",
        "category": ToolCategory.WEB.value,
        "capabilities": ["wordpress_scanning", "plugin_vulnerability", "theme_vulnerability"],
        "description": "WordPress security scanner.",
        "binary": "wpscan",
        "version_flag": "--version"
    },
    {
        "name": "droopescan",
        "category": ToolCategory.WEB.value,
        "capabilities": ["drupal_scanning", "joomla_scanning", "silverstripe_scanning"],
        "description": "Plugin-based scanner for Drupal, SilverStripe, and Joomla.",
        "binary": "droopescan",
        "version_flag": "--version"
    },
    {
        "name": "crlfuzz",
        "category": ToolCategory.WEB.value,
        "capabilities": ["crlf_injection", "http_response_splitting"],
        "description": "Fast tool to scan CRLF vulnerability written in Go.",
        "binary": "crlfuzz",
        "version_flag": "-version"
    },
    {
        "name": "x8",
        "category": ToolCategory.WEB.value,
        "capabilities": ["hidden_parameters", "param_bruteforce"],
        "description": "Hidden parameter discovery tool written in Rust.",
        "binary": "x8",
        "version_flag": "-v"
    },

    # --- NETWORK & INFRASTRUCTURE SCANNING ---
    {
        "name": "nmap",
        "category": ToolCategory.NETWORK.value,
        "capabilities": ["port_scanning", "service_detection", "os_fingerprinting", "nse_scripts"],
        "description": "Network exploration tool and security / port scanner.",
        "binary": "nmap",
        "version_flag": "--version"
    },
    {
        "name": "masscan",
        "category": ToolCategory.NETWORK.value,
        "capabilities": ["fast_port_scanning", "internet_scale_scanning"],
        "description": "TCP port scanner, spews SYN packets asynchronously, scanning entire Internet.",
        "binary": "masscan",
        "version_flag": "--version"
    },
    {
        "name": "rustscan",
        "category": ToolCategory.NETWORK.value,
        "capabilities": ["ultra_fast_port_scan", "nmap_integration"],
        "description": "Modern Port Scanner written in Rust.",
        "binary": "rustscan",
        "version_flag": "--version"
    },
    {
        "name": "zmap",
        "category": ToolCategory.NETWORK.value,
        "capabilities": ["network_scanner", "ipv4_scan"],
        "description": "Fast single packet network scanner designed for Internet-wide network surveys.",
        "binary": "zmap",
        "version_flag": "--version"
    },
    {
        "name": "netcat",
        "category": ToolCategory.NETWORK.value,
        "capabilities": ["port_banner_grabbing", "tcp_udp_testing"],
        "description": "Utility for reading from and writing to network connections using TCP or UDP.",
        "binary": "nc",
        "version_flag": "-h"
    },
    {
        "name": "snmpwalk",
        "category": ToolCategory.NETWORK.value,
        "capabilities": ["snmp_enumeration", "network_device_audit"],
        "description": "Retrieves a subtree of management values using SNMP GETNEXT requests.",
        "binary": "snmpwalk",
        "version_flag": "-V"
    },

    # --- RECONNAISSANCE & SUBDOMAIN DISCOVERY ---
    {
        "name": "subfinder",
        "category": ToolCategory.RECON.value,
        "capabilities": ["passive_subdomain_discovery", "recon", "domain_pulse"],
        "description": "Fast passive subdomain enumeration tool.",
        "binary": "subfinder",
        "version_flag": "-version"
    },
    {
        "name": "amass",
        "category": ToolCategory.RECON.value,
        "capabilities": ["subdomain_enumeration", "network_mapping", "active_passive_recon"],
        "description": "In-depth Attack Surface Mapping and Asset Discovery.",
        "binary": "amass",
        "version_flag": "-version"
    },
    {
        "name": "assetfinder",
        "category": ToolCategory.RECON.value,
        "capabilities": ["subdomain_discovery", "asset_discovery"],
        "description": "Find domains and subdomains related to a given domain.",
        "binary": "assetfinder",
        "version_flag": "--version"
    },
    {
        "name": "findomain",
        "category": ToolCategory.RECON.value,
        "capabilities": ["fast_subdomain_discovery", "recon"],
        "description": "The fastest and cross-platform subdomain enumerator.",
        "binary": "findomain",
        "version_flag": "--version"
    },
    {
        "name": "gau",
        "category": ToolCategory.RECON.value,
        "capabilities": ["url_mining", "archive_fetch", "endpoint_discovery"],
        "description": "GetAllUrls - Fetch known URLs from AlienVault's OTX, Wayback Machine, and Common Crawl.",
        "binary": "gau",
        "version_flag": "-version"
    },
    {
        "name": "waybackurls",
        "category": ToolCategory.RECON.value,
        "capabilities": ["historical_urls", "wayback_archive"],
        "description": "Fetch all URLs that the Wayback Machine knows about for a domain.",
        "binary": "waybackurls",
        "version_flag": "-h"
    },
    {
        "name": "shuffledns",
        "category": ToolCategory.RECON.value,
        "capabilities": ["dns_resolution", "subdomain_bruteforce"],
        "description": "MassDNS wrapper for active subdomain bruteforce and resolution.",
        "binary": "shuffledns",
        "version_flag": "-version"
    },
    {
        "name": "dnsx",
        "category": ToolCategory.RECON.value,
        "capabilities": ["dns_probing", "record_query", "wildcard_filtering"],
        "description": "Fast and multi-purpose DNS toolkit allow running multiple DNS queries.",
        "binary": "dnsx",
        "version_flag": "-version"
    },
    {
        "name": "naabu",
        "category": ToolCategory.RECON.value,
        "capabilities": ["fast_port_scan", "syn_probing"],
        "description": "Fast port scanner written in Go with focus on reliability and simplicity.",
        "binary": "naabu",
        "version_flag": "-version"
    },

    # --- DNS & DOMAIN INTELLIGENCE ---
    {
        "name": "dnsrecon",
        "category": ToolCategory.DNS.value,
        "capabilities": ["dns_enumeration", "zone_transfer", "spf_records", "srv_records"],
        "description": "DNS Enumeration and Scanning script.",
        "binary": "dnsrecon",
        "version_flag": "-v"
    },
    {
        "name": "dnstwist",
        "category": ToolCategory.DNS.value,
        "capabilities": ["typosquatting_detection", "domain_permutation", "brand_protection"],
        "description": "Domain name permutation engine for detecting typo squatting, phishing and corporate espionage.",
        "binary": "dnstwist",
        "version_flag": "--version"
    },
    {
        "name": "massdns",
        "category": ToolCategory.DNS.value,
        "capabilities": ["high_performance_dns", "bulk_resolution"],
        "description": "High-performance DNS stub resolver for bulk lookups and reconnaissance.",
        "binary": "massdns",
        "version_flag": "--version"
    },
    {
        "name": "fierce",
        "category": ToolCategory.DNS.value,
        "capabilities": ["dns_recon", "subdomain_enumeration"],
        "description": "A DNS reconnaissance tool for locating non-contiguous IP space.",
        "binary": "fierce",
        "version_flag": "--version"
    },
    {
        "name": "whois",
        "category": ToolCategory.DNS.value,
        "capabilities": ["whois_lookup", "registrar_info", "creation_expiration_date"],
        "description": "Client for the WHOIS directory service.",
        "binary": "whois",
        "version_flag": "-v"
    },
    {
        "name": "dig",
        "category": ToolCategory.DNS.value,
        "capabilities": ["dns_lookup", "record_retrieval", "trace_query"],
        "description": "DNS lookup utility for querying DNS name servers.",
        "binary": "dig",
        "version_flag": "-v"
    },

    # --- TLS & SSL SECURITY ---
    {
        "name": "testssl",
        "category": ToolCategory.TLS.value,
        "capabilities": ["ssl_vulnerability_audit", "cipher_suite_check", "tls_version_audit", "heartbleed", "robot"],
        "description": "Testing TLS/SSL encryption anywhere on any port.",
        "binary": "testssl.sh",
        "version_flag": "-v"
    },
    {
        "name": "sslscan",
        "category": ToolCategory.TLS.value,
        "capabilities": ["ssl_ciphers", "tls_negotiation", "certificate_validation"],
        "description": "Fast SSL/TLS cipher suite and vulnerability testing tool.",
        "binary": "sslscan",
        "version_flag": "--version"
    },
    {
        "name": "sslyze",
        "category": ToolCategory.TLS.value,
        "capabilities": ["fast_ssl_scanner", "tls_1_3_check", "certificate_chain_analysis"],
        "description": "Fast and powerful SSL/TLS scanning library and CLI.",
        "binary": "sslyze",
        "version_flag": "--version"
    },
    {
        "name": "certspotter",
        "category": ToolCategory.TLS.value,
        "capabilities": ["certificate_transparency", "ssl_monitoring"],
        "description": "Certificate Transparency Log monitor for unauthorized certificates.",
        "binary": "certspotter",
        "version_flag": "-version"
    },

    # --- STATIC ANALYSIS (SAST) ---
    {
        "name": "semgrep",
        "category": ToolCategory.SAST.value,
        "capabilities": ["sast", "code_security", "owasp_top_10", "cwe_detection", "pattern_matching"],
        "description": "Lightweight, open-source static analysis engine for finding bugs and enforcing code standards.",
        "binary": "semgrep",
        "version_flag": "--version"
    },
    {
        "name": "bandit",
        "category": ToolCategory.SAST.value,
        "capabilities": ["python_sast", "security_linting", "ast_analysis"],
        "description": "Security linter designed for Python source code analysis.",
        "binary": "bandit",
        "version_flag": "--version"
    },
    {
        "name": "gitleaks",
        "category": ToolCategory.SAST.value,
        "capabilities": ["secret_detection", "api_key_leak", "credential_scan", "git_history"],
        "description": "Fast tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos.",
        "binary": "gitleaks",
        "version_flag": "version"
    },
    {
        "name": "trufflehog",
        "category": ToolCategory.SAST.value,
        "capabilities": ["secret_scanning", "verified_secret_detection"],
        "description": "Find secrets and sensitive keys across git repositories and filesystems.",
        "binary": "trufflehog",
        "version_flag": "--version"
    },
    {
        "name": "flawfinder",
        "category": ToolCategory.SAST.value,
        "capabilities": ["c_cpp_sast", "buffer_overflow_detection"],
        "description": "Scans C/C++ source code and produces a list of potential security flaws.",
        "binary": "flawfinder",
        "version_flag": "--version"
    },
    {
        "name": "gosec",
        "category": ToolCategory.SAST.value,
        "capabilities": ["golang_sast", "security_audit"],
        "description": "Security checker for Go source code.",
        "binary": "gosec",
        "version_flag": "-version"
    },
    {
        "name": "brakeman",
        "category": ToolCategory.SAST.value,
        "capabilities": ["ruby_rails_sast", "vulnerability_scanner"],
        "description": "Static analysis security vulnerability scanner for Ruby on Rails applications.",
        "binary": "brakeman",
        "version_flag": "--version"
    },

    # --- SOFTWARE COMPOSITION ANALYSIS (SCA) & DEPENDENCIES ---
    {
        "name": "trivy",
        "category": ToolCategory.SCA.value,
        "capabilities": ["container_scan", "sbom_generation", "sca_dependency_scan", "cve_lookup", "iac_misconfig"],
        "description": "Comprehensive security scanner for vulnerabilities in container images, file systems, and Git repositories.",
        "binary": "trivy",
        "version_flag": "--version"
    },
    {
        "name": "osv-scanner",
        "category": ToolCategory.SCA.value,
        "capabilities": ["sca_audit", "google_osv_database", "dependency_cve"],
        "description": "Vulnerability scanner powered by Google's OSV database across package ecosystems.",
        "binary": "osv-scanner",
        "version_flag": "--version"
    },
    {
        "name": "pip-audit",
        "category": ToolCategory.SCA.value,
        "capabilities": ["python_sca", "pypi_advisory_database", "requirements_audit"],
        "description": "Audits Python environments and dependency files for known vulnerabilities.",
        "binary": "pip-audit",
        "version_flag": "--version"
    },
    {
        "name": "npm-audit",
        "category": ToolCategory.SCA.value,
        "capabilities": ["nodejs_sca", "package_json_audit"],
        "description": "Node Package Manager vulnerability audit engine.",
        "binary": "npm",
        "version_flag": "--version"
    },
    {
        "name": "grype",
        "category": ToolCategory.SCA.value,
        "capabilities": ["sbom_vulnerability_scan", "container_sca"],
        "description": "A vulnerability scanner for container images and filesystems.",
        "binary": "grype",
        "version_flag": "version"
    },
    {
        "name": "syft",
        "category": ToolCategory.SCA.value,
        "capabilities": ["sbom_generation", "package_inventory"],
        "description": "CLI tool and library for generating a Software Bill of Materials from container images and filesystems.",
        "binary": "syft",
        "version_flag": "version"
    },

    # --- OSINT & THREAT INTELLIGENCE ---
    {
        "name": "theharvester",
        "category": ToolCategory.OSINT.value,
        "capabilities": ["email_harvesting", "subdomain_osint", "employee_lookup", "threat_intel"],
        "description": "E-mails, subdomains and names Harvester - OSINT tool.",
        "binary": "theHarvester",
        "version_flag": "-h"
    },
    {
        "name": "spiderfoot",
        "category": ToolCategory.OSINT.value,
        "capabilities": ["automated_osint", "threat_intelligence", "attack_surface_mapping"],
        "description": "Open source intelligence automation tool.",
        "binary": "spiderfoot",
        "version_flag": "--version"
    },
    {
        "name": "recon-ng",
        "category": ToolCategory.OSINT.value,
        "capabilities": ["modular_recon", "osint_framework"],
        "description": "Full-featured Web Reconnaissance framework written in Python.",
        "binary": "recon-ng",
        "version_flag": "--version"
    },
    {
        "name": "sherlock",
        "category": ToolCategory.OSINT.value,
        "capabilities": ["social_media_osint", "username_investigation"],
        "description": "Hunt down social media accounts by username across social networks.",
        "binary": "sherlock",
        "version_flag": "--version"
    },

    # --- CLOUD & CONTAINER SECURITY ---
    {
        "name": "prowler",
        "category": ToolCategory.CLOUD.value,
        "capabilities": ["aws_security_assessment", "azure_gcp_cis_benchmark", "cloud_compliance"],
        "description": "Security tool to perform AWS, Azure and GCP security assessment, auditing and hardening.",
        "binary": "prowler",
        "version_flag": "-v"
    },
    {
        "name": "scoutsuite",
        "category": ToolCategory.CLOUD.value,
        "capabilities": ["multi_cloud_auditing", "cloud_posture_management"],
        "description": "Open source multi-cloud security-auditing tool.",
        "binary": "scout",
        "version_flag": "--version"
    },
    {
        "name": "dockle",
        "category": ToolCategory.CONTAINER.value,
        "capabilities": ["container_linter", "cis_docker_benchmark"],
        "description": "Container Image Linter for Security, Helping build the Best-Practice Docker Image.",
        "binary": "dockle",
        "version_flag": "-v"
    },
    {
        "name": "hadolint",
        "category": ToolCategory.CONTAINER.value,
        "capabilities": ["dockerfile_linter", "docker_security_best_practices"],
        "description": "Dockerfile linter, validate inline bash, written in Haskell.",
        "binary": "hadolint",
        "version_flag": "--version"
    }
]


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._initialized = False
        self._load_registry()

    def _load_registry(self):
        """Populate tools and detect presence on system without blocking."""
        for meta in TOOLS_METADATA:
            name = meta["name"]
            binary = meta.get("binary", name)
            bin_path = shutil.which(binary)
            
            # Additional path lookups for common security tools in user environments
            if not bin_path:
                common_paths = [
                    f"/usr/local/bin/{binary}",
                    f"/opt/homebrew/bin/{binary}",
                    f"/usr/bin/{binary}",
                    f"{os.path.expanduser('~')}/go/bin/{binary}",
                    f"{os.path.expanduser('~')}/.cargo/bin/{binary}",
                    f"{os.path.expanduser('~')}/.local/bin/{binary}"
                ]
                for cp in common_paths:
                    if os.path.isfile(cp) and os.access(cp, os.X_OK):
                        bin_path = cp
                        break

            installed = bin_path is not None
            
            tool_def = ToolDefinition(
                name=name,
                category=meta["category"],
                capabilities=meta["capabilities"],
                hexstrike_supported=True,
                installed=installed,
                version="Available" if installed else None,
                description=meta["description"],
                binary_path=bin_path,
                execution_type="cli",
                last_checked=datetime.now(timezone.utc).isoformat()
            )
            self._tools[name] = tool_def

        self._initialized = True

    def refresh_availability(self):
        """Force re-check of installed binaries."""
        self._load_registry()

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name.lower())

    def get_all_tools(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def get_tools_by_category(self, category: str) -> List[ToolDefinition]:
        cat = category.upper()
        return [t for t in self._tools.values() if t.category.upper() == cat]

    def get_available_tools(self) -> List[ToolDefinition]:
        return [t for t in self._tools.values() if t.installed]

    def get_unavailable_tools(self) -> List[ToolDefinition]:
        return [t for t in self._tools.values() if not t.installed]

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._tools)
        available = len(self.get_available_tools())
        unavailable = total - available

        category_counts: Dict[str, Dict[str, int]] = {}
        for t in self._tools.values():
            if t.category not in category_counts:
                category_counts[t.category] = {"total": 0, "available": 0}
            category_counts[t.category]["total"] += 1
            if t.installed:
                category_counts[t.category]["available"] += 1

        return {
            "total_tools": total,
            "available_tools": available,
            "unavailable_tools": unavailable,
            "availability_ratio": round((available / total) * 100, 1) if total > 0 else 0,
            "categories": category_counts
        }

# Global Singleton instance
tool_registry = ToolRegistry()

---
name: hexstrike-ai
description: HexStrike AI v6.0 cybersecurity automation skill. Provides full orchestration for 150+ professional security tools, 12+ autonomous AI agents (BugBounty, CTF Solver, CVE Intelligence, Exploit Generator, Cloud Security, Binary Analysis, OSINT), FastMCP protocol integration, and attack chain decision engines. Activate when the user asks to perform security scanning, penetration testing, vulnerability assessment, CTF solving, CVE lookup, exploit analysis, or tool orchestration.
---

# HexStrike AI v6.0 - Advanced Cybersecurity Automation Platform

HexStrike AI is a comprehensive AI-driven offensive & defensive security platform bridging Large Language Models with 150+ professional security tools, 12+ specialized autonomous AI agents, and a complete Application Security (AppSec) & Asset Monitoring suite via the Model Context Protocol (MCP) and REST API.

## Architecture Overview

```
[ AI Model / Agent (Claude / GPT / Copilot / Gemini) ]
                         │  (FastMCP / stdio / HTTP)
                         ▼
             [ hexstrike_mcp.py ] (FastMCP Server)
                         │  (REST API: http://127.0.0.1:3000)
                         ▼
             [ hexstrike_server.py ] (Flask API + Decision Engine)
        ├── Intelligent Decision Engine (Tool Selection, Parameter Optimization)
        ├── 12+ Autonomous AI Agents (BugBounty, CTF, CVE, Exploit, Cloud, etc.)
        ├── AppSec & Monitoring Engine (SAST, DAST, SCA, CSV Feed, DNS, SSL)
        ├── 150+ Security Tools Subprocess Engine (Recovery, Smart Caching)
        └── ModernVisualEngine (Telemetry, Color Themes, Progress Bars)
```

## Running the Platform

### 1. Start the HexStrike Server
```bash
# Activate python environment
python -m venv hexstrike-env
.\hexstrike-env\Scripts\activate   # Windows
# or: source hexstrike-env/bin/activate # Linux/macOS

pip install -r requirements.txt

# Launch Server (Default port 3000)
python hexstrike_server.py --port 3000
```

### 2. Connect MCP Client
```bash
python hexstrike_mcp.py --server http://127.0.0.1:3000
```

## 🛡️ AppSec & Asset Monitoring Suite

HexStrike AI v6.0 includes dedicated built-in application security and continuous monitoring modules:

### 1. Advanced SAST Engine (`tools/sast_scanner.py`)
- **Capabilities:** Static source code vulnerability scanner for Python, JS/TS, Java, PHP, Go, Ruby, C/C++, HTML, YAML, and ENV files.
- **Coverage:** Hardcoded credentials/AWS keys, SQL/NoSQL injection patterns, command injections, unsafe deserialization (pickle, yaml, Java/PHP), insecure crypto (MD5/SHA1/DES), path traversal, XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`), and SSRF sinks.
- **MCP Tool:** `sast_scan(target_path, min_severity)`
- **Endpoint:** `POST /api/tools/sast`

### 2. Comprehensive DAST Engine (`tools/dast_scanner.py`)
- **Capabilities:** Non-destructive runtime security and configuration auditing.
- **Coverage:** Missing security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), overly permissive CORS, cookie security flags (`Secure`, `HttpOnly`, `SameSite`), exposed sensitive files (`.env`, `.git`, `.DS_Store`, SQL dumps, actuator endpoints), CSRF form validation, and passive injection/SSRF indicators.
- **MCP Tool:** `dast_scan(target_url, auth_token, check_sensitive_files, max_crawl_pages)`
- **Endpoint:** `POST /api/tools/dast`

### 3. SCA & Supply Chain Engine (`tools/sca_scanner.py`)
- **Capabilities:** Manifest parser for `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `composer.json`.
- **Coverage:** Cross-references installed dependencies against CVE/GHSA/OSV databases, flags vulnerable versions, and computes recommended upgrade versions.
- **MCP Tool:** `sca_scan(manifest_path, target_dir)`
- **Endpoint:** `POST /api/tools/sca`

### 4. CSV Telemetry & Feed Monitor (`tools/csv_monitor.py`)
- **Capabilities:** Ingests vulnerability exports (Nessus, Qualys, Burp) and asset inventory logs.
- **Coverage:** Schema auto-detection, anomaly detection (IP/port validity, severity spikes), and delta diffs (new vs resolved vs persistent findings).
- **MCP Tool:** `monitor_csv_feed(file_path, baseline_path)`
- **Endpoint:** `POST /api/tools/csv-monitor`

### 5. Domain Issues & DNS Monitor (`tools/dns_monitor.py`)
- **Capabilities:** DNS health, email authentication posture, and domain lifecycle checks.
- **Coverage:** A/AAAA/MX/TXT/NS resolution, SPF policy audit (`+all`, `~all`, `-all`), DMARC policy mode (`p=reject/quarantine/none`), subdomain takeover risk detection (GitHub Pages, Heroku, S3, Azure), and high-risk typosquatting domain permutations.
- **MCP Tool:** `check_domain_health(domain)`
- **Endpoint:** `POST /api/tools/dns-monitor`

### 6. SSL/TLS Certificate Monitor (`tools/ssl_monitor.py`)
- **Capabilities:** Deep inspection of SSL/TLS endpoints and cipher suites.
- **Coverage:** Certificate validity, chain validation, expiry countdown (flags expired, < 7d, < 30d), SAN coverage, deprecated protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1), and weak cipher detection (RC4, 3DES, DES, NULL, EXPORT).
- **MCP Tool:** `check_ssl_certificate(domain_or_ip, port)`
- **Endpoint:** `POST /api/tools/ssl-monitor`

### 7. Unified AppSec Reporter (`tools/unified_reporter.py`)
- **Capabilities:** Aggregates and consolidates findings across all 6 modules.
- **Coverage:** Calculates unified Security Posture Score (0-100), maps all issues to CVSS v3.1 severity ranges, and produces formatted Markdown Card Summaries and JSON dashboards.
- **MCP Tool:** `unified_appsec_audit(project_name, target_url, source_path, manifest_path, domain, csv_file, ssl_target)`
- **Endpoint:** `POST /api/tools/appsec-unified-audit`

---

## AI Agent Roster & Workflows

HexStrike AI incorporates 12+ specialized multi-agent workflows:

1. **Bug Bounty Manager Agent**
   - Subdomain enumeration, live host discovery, web crawling, parameter fuzzing, and vulnerability template execution (`nuclei`).
   - Endpoint: `/api/agents/bugbounty`

2. **CTF Solver Agent**
   - Automated flag hunting, crypto/decoding analysis, binary inspection, reverse engineering, web challenge automation.
   - Endpoint: `/api/agents/ctf-solver`

3. **CVE Intelligence Agent**
   - Real-time vulnerability lookup (NVD, GitHub Advisories, ExploitDB), severity score parsing, exploitability assessment.
   - Endpoint: `/api/agents/cve-intelligence`

4. **AI Exploit Generator Agent**
   - Custom exploit generation, payload encoding (Base64, URL, Hex, Polyglot), WAF bypass generation, reverse shells.
   - Endpoint: `/api/agents/exploit-generator`

5. **Web Application Pentester Agent**
   - DAST testing, SQLi (`sqlmap`), XSS (`dalfox`), directory fuzzing (`ffuf`, `gobuster`), CMS scanning (`wpscan`), parameter discovery (`arjun`).
   - Endpoint: `/api/agents/web-pentest`

6. **Network Reconnaissance Agent**
   - Port scanning (`nmap`, `rustscan`, `masscan`), service fingerprinting, SMB/RPC enumeration (`enum4linux-ng`, `smbmap`).
   - Endpoint: `/api/agents/network-recon`

7. **Cloud Security Auditor Agent**
   - Multi-cloud posture scanning (`prowler`, `scout-suite`, `trivy`), Kubernetes (`kube-hunter`), container security (`docker-bench-security`).
   - Endpoint: `/api/agents/cloud-audit`

8. **Binary Analysis & Reverse Engineering Agent**
   - Disassembly, decompilation, binary security check (`checksec`, `ghidra`, `radare2`), firmware extraction (`binwalk`), memory forensics (`volatility3`).
   - Endpoint: `/api/agents/binary-analysis`

9. **OSINT & Intelligence Gathering Agent**
   - Domain intelligence, certificate transparency, email harvesting (`theharvester`, `amass`), metadata analysis (`exiftool`).
   - Endpoint: `/api/agents/osint`

10. **Password & Credential Recovery Agent**
    - Password hash identification (`hash-identifier`), cracking (`hashcat`, `john`), online authentication bruteforce (`hydra`).
    - Endpoint: `/api/agents/credentials`

---

## Tool Arsenal Reference (150+ Tools)

### AppSec & Monitoring Suite
- `sast_scan(target_path, min_severity)`
- `dast_scan(target_url, auth_token, check_sensitive_files, max_crawl_pages)`
- `sca_scan(manifest_path, target_dir)`
- `monitor_csv_feed(file_path, baseline_path)`
- `check_domain_health(domain)`
- `check_ssl_certificate(domain_or_ip, port)`
- `unified_appsec_audit(project_name, target_url, source_path, manifest_path, domain, csv_file, ssl_target)`

### Network & Reconnaissance
- `nmap_scan(target, scan_type, ports, additional_args)`
- `rustscan_scan(target, ports, additional_args)`
- `masscan_scan(target, ports, rate, additional_args)`
- `amass_scan(domain, mode, additional_args)`
- `subfinder_scan(domain, additional_args)`
- `autorecon_scan(target, additional_args)`
- `enum4linux_scan(target, additional_args)`
- `smbmap_scan(target, username, password, domain)`

### Web Security Testing
- `gobuster_scan(url, mode, wordlist, additional_args)`
- `feroxbuster_scan(url, wordlist, additional_args)`
- `ffuf_scan(url, wordlist, filter_mode, additional_args)`
- `dirsearch_scan(url, wordlist, additional_args)`
- `nuclei_scan(target, severity, tags, template, additional_args)`
- `sqlmap_scan(url, data, parameter, level, risk, additional_args)`
- `dalfox_scan(url, mode, additional_args)`
- `wpscan_scan(url, enumerate, api_token, additional_args)`
- `arjun_scan(url, method, additional_args)`
- `wafw00f_scan(url, additional_args)`
- `httpx_probe(targets, additional_args)`
- `katana_crawl(url, depth, additional_args)`

### Cloud & Container
- `prowler_scan(provider, profile, region, checks, output_dir)`
- `scoutsuite_scan(provider, profile, report_dir)`
- `trivy_scan(target, scan_type, severity)`
- `kube_hunter_scan(target, scan_mode)`

### Reverse Engineering & Forensics
- `radare2_analyze(file_path, command)`
- `ghidra_analyze(file_path, script_path)`
- `checksec_analyze(file_path)`
- `binwalk_scan(file_path, extract)`
- `volatility_analyze(memory_file, profile, plugin)`
- `exiftool_scan(file_path)`

### Password & Authentication
- `hydra_attack(target, service, userlist, passlist, additional_args)`
- `john_crack(hash_file, wordlist, format)`
- `hashcat_crack(hash_file, mode, wordlist, rules)`

## Error Recovery & Intelligent Caching
HexStrike includes automated error recovery:
- Automatic timeout extension and parameter fallback
- Alternative tool recommendation when specific tools fail
- Response caching to avoid redundant heavy scanning

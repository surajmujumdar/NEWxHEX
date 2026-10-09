#!/usr/bin/env python3
"""
HexStrike AI - Advanced SAST Scanner Module (Static Application Security Testing)
================================================================================
Comprehensive source code vulnerability analysis engine mapped to OWASP Top 10.
Analyzes Python, JavaScript/TypeScript, Java, PHP, Go, Ruby, C/C++, HTML, YAML, and ENV files.
"""

import os
import re
import sys
import json
import math
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

try:
    from .repo_fetcher import is_git_or_github_url, fetch_or_clone_repo, cleanup_repo, parse_repo_info
except (ImportError, ValueError):
    try:
        from tools.repo_fetcher import is_git_or_github_url, fetch_or_clone_repo, cleanup_repo, parse_repo_info
    except (ImportError, ValueError):
        from repo_fetcher import is_git_or_github_url, fetch_or_clone_repo, cleanup_repo, parse_repo_info



@dataclass
class SASTFinding:
    """Represents a single static analysis security finding"""
    rule_id: str
    title: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float      # 0.0 - 10.0
    owasp_category: str    # e.g. A03:2021-Injection
    cwe_id: str            # e.g. CWE-89
    file_path: str
    line_number: int
    column_number: int
    matched_snippet: str
    code_context: List[str]
    description: str
    remediation: str
    confidence: str        # HIGH, MEDIUM, LOW

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SASTRuleEngine:
    """Detection rules catalog for SAST vulnerabilities across multiple languages"""

    @staticmethod
    def get_rules() -> List[Dict[str, Any]]:
        return [
            # =================================================================
            # 1. HARDCODED SECRETS & CREDENTIALS (CRITICAL / HIGH)
            # =================================================================
            {
                "id": "SEC-001",
                "title": "AWS Access Key ID Detected",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-798",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"
                ],
                "description": "Found a hardcoded AWS Access Key ID. Hardcoded credentials can allow unauthorized cloud infrastructure access.",
                "remediation": "Move AWS credentials to environment variables, AWS Secrets Manager, or IAM instance profiles."
            },
            {
                "id": "SEC-002",
                "title": "Hardcoded Private Key or Certificate Block",
                "owasp": "A02:2021-Cryptographic Failures",
                "cwe": "CWE-321",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
                ],
                "description": "A private cryptographic key block is embedded directly in source code or repository files.",
                "remediation": "Store private keys securely in a secrets manager or HSM. Never commit private keys to source control."
            },
            {
                "id": "SEC-003",
                "title": "Hardcoded JWT Secret or Cryptographic Signing Key",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "cwe": "CWE-798",
                "severity": "CRITICAL",
                "cvss": 9.2,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"(?i)(?:jwt_secret|jwt_key|secret_key|jwt_secret_key)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                    r"(?i)jwt\.encode\s*\(.*?['\"][A-Za-z0-9_\-]{16,}['\"]"
                ],
                "description": "Static JWT signing secret hardcoded in code allows adversaries to forge administrative tokens.",
                "remediation": "Inject JWT secret dynamically from environment variables or a key vault."
            },
            {
                "id": "SEC-004",
                "title": "Database Connection String with Plaintext Credentials",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "cwe": "CWE-798",
                "severity": "HIGH",
                "cvss": 8.5,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^:\s]+:[^@\s]+@[a-zA-Z0-9.-]+",
                    r"(?:jdbc:[a-z]+://[^?]+[?&]password=[^&\s]+)"
                ],
                "description": "Database connection URI contains hardcoded authentication credentials (username/password).",
                "remediation": "Use external environment variables or a vault to inject database credentials at runtime."
            },
            {
                "id": "SEC-005",
                "title": "Generic Secret, OAuth Secret or API Token Assignment",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "cwe": "CWE-798",
                "severity": "HIGH",
                "cvss": 7.5,
                "confidence": "MEDIUM",
                "languages": ["all"],
                "patterns": [
                    r"(?i)(?:api_key|apikey|secret_key|client_secret|auth_token|access_token|private_token|stripe_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.\/]{16,}['\"]"
                ],
                "description": "Detected hardcoded API key, client secret, or access token.",
                "remediation": "Store tokens in secure environment configurations or encrypted credential vaults."
            },
            {
                "id": "SEC-006",
                "title": "Exposed Webhook or Bot Token (Slack / Discord / Telegram)",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-798",
                "severity": "HIGH",
                "cvss": 7.4,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
                    r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}",
                    r"\d{9,10}:[A-Za-z0-9_-]{35}"
                ],
                "description": "Found communication platform webhook or bot token exposed in code.",
                "remediation": "Revoke the exposed webhook/token immediately and configure it via protected environment variables."
            },

            # =================================================================
            # 2. INJECTION VULNERABILITIES (CRITICAL / HIGH)
            # =================================================================
            {
                "id": "INJ-001",
                "title": "SQL Injection - Dynamic String Concatenation in Query",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-89",
                "severity": "CRITICAL",
                "cvss": 9.4,
                "confidence": "HIGH",
                "languages": [".py", ".js", ".ts", ".php", ".java", ".go", ".rb", ".cs"],
                "patterns": [
                    r"(?i)(?:execute|raw_query|query)\s*\(\s*f['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*?\{.*?\}",
                    r"(?i)(?:execute|query)\s*\(\s*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+.*?['\"]\s*%\s*",
                    r"(?i)(?:execute|query)\s*\(\s*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+.*?['\"]\s*\.format\s*\(",
                    r"(?i)(?:db\.)?(?:query|execute|raw)\s*\(\s*`.*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+.*?\$\{.*?\}",
                    r"(?i)(?:mysqli_query|pg_query|mysql_query)\s*\(.*?\$.*?\.\s*\$",
                    r"(?i)createStatement\s*\(\s*\)\s*\.executeQuery\s*\(.*?[\+\$]"
                ],
                "description": "Constructing SQL queries with unescaped string formatting or concatenation allows attackers to manipulate database queries.",
                "remediation": "Use parameterized queries (prepared statements) or ORM parameter binding."
            },
            {
                "id": "INJ-002",
                "title": "Command Injection - Insecure Subprocess with Shell=True",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-78",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "confidence": "HIGH",
                "languages": [".py"],
                "patterns": [
                    r"(?i)subprocess\.(?:Popen|call|check_call|check_output|run)\s*\(.*shell\s*=\s*True",
                    r"(?i)os\.system\s*\(.*?(?:\+|%|\.format|f['\"])",
                    r"(?i)os\.popen\s*\(.*?(?:\+|%|\.format|f['\"])"
                ],
                "description": "Executing system commands with shell=True or passing formatted strings to os.system enables command injection via shell metacharacters.",
                "remediation": "Pass arguments as a list with shell=False (default): subprocess.run(['cmd', arg1, arg2], check=True)."
            },
            {
                "id": "INJ-003",
                "title": "Command Injection - NodeJS child_process Execution",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-78",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "confidence": "HIGH",
                "languages": [".js", ".ts"],
                "patterns": [
                    r"(?i)(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*[`'\"].*?(?:\$\{|\+|req\.)",
                    r"(?i)\bexec\s*\(\s*`.*?\$\{.*?\}\s*`"
                ],
                "description": "NodeJS child_process.exec invokes a shell interpreter. Dynamic variables in the command string allow arbitrary command execution.",
                "remediation": "Use child_process.execFile or child_process.spawn with an argument array instead."
            },
            {
                "id": "INJ-004",
                "title": "Dynamic Code Execution via Eval / Exec",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-95",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "confidence": "HIGH",
                "languages": [".py", ".js", ".ts", ".php", ".rb"],
                "patterns": [
                    r"(?i)\beval\s*\(\s*(?:req\.|params|\$_GET|\$_POST|input|request|data|[a-zA-Z0-9_]+)",
                    r"(?i)\bexec\s*\(\s*(?:req\.|params|\$_GET|\$_POST|input|request|data|[a-zA-Z0-9_]+)",
                    r"(?i)new\s+Function\s*\(.*?(?:req\.|input|params)"
                ],
                "description": "Directly evaluating user-supplied strings as code (eval/exec) allows complete arbitrary code execution.",
                "remediation": "Refactor code to avoid dynamic evaluation. Use structured parsers (e.g. json.loads) for data processing."
            },
            {
                "id": "INJ-005",
                "title": "NoSQL Injection - Dynamic Clause Evaluation",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-943",
                "severity": "HIGH",
                "cvss": 8.6,
                "confidence": "MEDIUM",
                "languages": [".js", ".ts", ".py", ".php"],
                "patterns": [
                    r"(?i)\$where\s*:\s*['\"].*?(?:\+|\$|req\.)",
                    r"(?i)collection\.(?:find|update|remove)\s*\(\s*\{\s*\$where\s*:",
                    r"(?i)db\.eval\s*\("
                ],
                "description": "Using dynamic strings inside NoSQL $where clauses or db.eval() allows server-side JavaScript execution in MongoDB.",
                "remediation": "Avoid $where and db.eval. Use standard query operators ($eq, $in, etc.) with explicit type validation."
            },

            # =================================================================
            # 3. DESERIALIZATION & INTEGRITY FAILURES (CRITICAL / HIGH)
            # =================================================================
            {
                "id": "DESER-001",
                "title": "Insecure Python Object Deserialization (Pickle/Shelve)",
                "owasp": "A08:2021-Software and Data Integrity Failures",
                "cwe": "CWE-502",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "confidence": "HIGH",
                "languages": [".py"],
                "patterns": [
                    r"(?i)\bpickle\.(?:loads|load)\s*\(",
                    r"(?i)\b_pickle\.(?:loads|load)\s*\(",
                    r"(?i)\bcPickle\.(?:loads|load)\s*\(",
                    r"(?i)\bshelve\.open\s*\("
                ],
                "description": "Deserializing untrusted data with pickle allows arbitrary code execution via Python reduction protocol (__reduce__).",
                "remediation": "Never unpickle untrusted inputs. Use secure data formats such as JSON or Protocol Buffers."
            },
            {
                "id": "DESER-002",
                "title": "Unsafe YAML Deserialization",
                "owasp": "A08:2021-Software and Data Integrity Failures",
                "cwe": "CWE-502",
                "severity": "HIGH",
                "cvss": 8.8,
                "confidence": "HIGH",
                "languages": [".py"],
                "patterns": [
                    r"(?i)yaml\.load\s*\([^,)]*\)",
                    r"(?i)yaml\.load\s*\(.*Loader\s*=\s*(?:yaml\.)?(?:Loader|CLoader|UnsafeLoader)"
                ],
                "description": "PyYAML's yaml.load without SafeLoader can instantiate arbitrary Python objects leading to RCE.",
                "remediation": "Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader)."
            },

            # =================================================================
            # 4. ACCESS CONTROL, PATH TRAVERSAL, XSS & SSRF (HIGH)
            # =================================================================
            {
                "id": "PATH-001",
                "title": "Path Traversal / Unvalidated File Path Access",
                "owasp": "A01:2021-Broken Access Control",
                "cwe": "CWE-22",
                "severity": "HIGH",
                "cvss": 7.5,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".php", ".java"],
                "patterns": [
                    r"(?i)open\s*\(\s*(?:os\.path\.join\s*\(.*?(?:request|req|params|user_input)|(?:request|req|params)\.)",
                    r"(?i)fs\.(?:readFile|readFileSync|createReadStream)\s*\(.*?(?:req\.query|req\.params|req\.body)",
                    r"(?i)send_file\s*\(\s*.*?request\.(?:args|form|values)",
                    r"(?i)res\.sendFile\s*\(.*?(?:req\.query|req\.params)",
                    r"(?i)file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)"
                ],
                "description": "User-controlled input combined into file system calls allows directory traversal to access unauthorized files.",
                "remediation": "Canonicalize paths using os.path.realpath / path.resolve and verify they remain within intended base directory."
            },
            {
                "id": "XSS-001",
                "title": "DOM-Based XSS Sink (innerHTML / dangerouslySetInnerHTML)",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "cvss": 7.2,
                "confidence": "HIGH",
                "languages": [".js", ".ts", ".jsx", ".tsx", ".html", ".vue"],
                "patterns": [
                    r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
                    r"(?i)\.innerHTML\s*=\s*(?:location|document\.|window\.|[a-zA-Z0-9_]+\.(?:param|query|data))",
                    r"(?i)document\.write\s*\(",
                    r"v-html\s*=\s*['\"]"
                ],
                "description": "Assigning unescaped or user-controllable data to DOM rendering sinks executes malicious scripts in client browsers.",
                "remediation": "Use safe DOM methods (textContent, innerText) or sanitize HTML with DOMPurify."
            },
            {
                "id": "SSRF-001",
                "title": "Potential Server-Side Request Forgery (SSRF) Sink",
                "owasp": "A10:2021-Server-Side Request Forgery",
                "cwe": "CWE-918",
                "severity": "HIGH",
                "cvss": 8.6,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".php", ".go", ".java"],
                "patterns": [
                    r"(?i)requests\.(?:get|post|put|patch|delete)\s*\(\s*(?:request|req|params|url_input)",
                    r"(?i)(?:axios|fetch)\s*\(\s*(?:req\.query|req\.body|req\.params)",
                    r"(?i)curl_init\s*\(\s*\$_(?:GET|POST|REQUEST)",
                    r"(?i)http\.(?:Get|Post)\s*\(\s*(?:r\.URL|r\.Form|targetURL)"
                ],
                "description": "Passing user-controlled URLs to outgoing HTTP request clients allows attackers to probe internal networks or cloud metadata endpoints.",
                "remediation": "Validate destination URLs against a strict whitelist. Block RFC-1918 private IPs, localhost, and cloud metadata (169.254.169.254)."
            },

            # =================================================================
            # 5. MEDIUM SEVERITY VULNERABILITIES & CONFIGURATIONS
            # =================================================================
            {
                "id": "MED-001",
                "title": "Broken/Weak Cryptographic Hash (MD5 / SHA1)",
                "owasp": "A02:2021-Cryptographic Failures",
                "cwe": "CWE-328",
                "severity": "MEDIUM",
                "cvss": 5.9,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".java", ".php", ".go", ".cs"],
                "patterns": [
                    r"(?i)hashlib\.(?:md5|sha1)\s*\(",
                    r"(?i)crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)",
                    r"(?i)MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1)['\"]\s*\)",
                    r"(?i)\bmd5\s*\(\s*\$",
                    r"(?i)\bsha1\s*\(\s*\$"
                ],
                "description": "MD5 and SHA-1 are cryptographically weak due to collision attacks.",
                "remediation": "Upgrade to SHA-256 (SHA-2), SHA-3, or BLAKE2. For passwords, use Argon2id or bcrypt."
            },
            {
                "id": "MED-002",
                "title": "Insecure Permissive CORS Configuration (Wildcard with Credentials)",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-942",
                "severity": "MEDIUM",
                "cvss": 6.5,
                "confidence": "HIGH",
                "languages": [".py", ".js", ".ts"],
                "patterns": [
                    r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]\s*,\s*allow_credentials\s*=\s*True",
                    r"(?i)origin\s*:\s*['\"].*?\*['\"].*?credentials\s*:\s*true"
                ],
                "description": "Configuring wildcard CORS origins alongside credentials exposes cross-origin authenticated session requests.",
                "remediation": "Explicitly define allowed client origins and restrict credential forwarding."
            },
            {
                "id": "MED-003",
                "title": "Server-Side Template XSS / Disabled Autoescaping",
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "confidence": "HIGH",
                "languages": [".html", ".jinja", ".j2", ".py", ".php"],
                "patterns": [
                    r"\{\{.*?\|\s*safe\s*\}\}",
                    r"\{\{.*?\|\s*raw\s*\}\}",
                    r"autoescape\s*=\s*False",
                    r"<\?=\s*\$_(?:GET|POST|REQUEST)\["
                ],
                "description": "Disabling template engine auto-escaping or marking untrusted variables as | safe permits reflected or stored XSS.",
                "remediation": "Enable auto-escaping on template engines and sanitize user variables before rendering."
            },
            {
                "id": "MED-004",
                "title": "Insecure XML External Entity (XXE) Processing",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-611",
                "severity": "MEDIUM",
                "cvss": 6.5,
                "confidence": "HIGH",
                "languages": [".py", ".java", ".php"],
                "patterns": [
                    r"(?i)xml\.etree\.ElementTree\.(?:parse|fromstring)\s*\(",
                    r"(?i)lxml\.etree\.fromstring\s*\(.*resolve_entities\s*=\s*True"
                ],
                "description": "Standard XML parsers may evaluate external entity declarations leading to file disclosure or SSRF.",
                "remediation": "Use defusedxml in Python or disable external DTDs and entities in XML parsers."
            },
            {
                "id": "MED-005",
                "title": "CSRF Protection Explicitly Disabled / Exemption",
                "owasp": "A01:2021-Broken Access Control",
                "cwe": "CWE-352",
                "severity": "MEDIUM",
                "cvss": 6.2,
                "confidence": "HIGH",
                "languages": [".py", ".js", ".ts", ".php"],
                "patterns": [
                    r"@csrf_exempt\b",
                    r"(?i)csrf\s*:\s*false\b",
                    r"(?i)disable_csrf\s*=\s*True"
                ],
                "description": "Disabling CSRF middleware or exempting endpoints exposes state-modifying requests to Cross-Site Request Forgery.",
                "remediation": "Enforce anti-CSRF tokens on all POST/PUT/DELETE state-changing routes."
            },

            # =================================================================
            # 6. LOW SEVERITY VULNERABILITIES & HYGIENE ISSUES
            # =================================================================
            {
                "id": "LOW-001",
                "title": "Insecure Pseudo-Random Number Generator (PRNG) for Tokens",
                "owasp": "A02:2021-Cryptographic Failures",
                "cwe": "CWE-338",
                "severity": "LOW",
                "cvss": 3.7,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".java"],
                "patterns": [
                    r"(?i)(?:token|secret|password|key|session)\s*=\s*.*?random\.(?:randint|random|choice)",
                    r"(?i)(?:token|secret|password|key|session)\s*=\s*.*?Math\.random\s*\("
                ],
                "description": "Standard random modules (random, Math.random) are predictable PRNGs unsuitable for security tokens or password generation.",
                "remediation": "Use cryptographically secure PRNGs: secrets module in Python, crypto.randomBytes in Node.js, or SecureRandom in Java."
            },
            {
                "id": "LOW-002",
                "title": "Insecure Temporary File Creation",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-377",
                "severity": "LOW",
                "cvss": 3.3,
                "confidence": "HIGH",
                "languages": [".py", ".c", ".cpp"],
                "patterns": [
                    r"(?i)tempfile\.mktemp\s*\(",
                    r"(?i)\btmpnam\s*\("
                ],
                "description": "mktemp and tmpnam are susceptible to race conditions and symlink attacks.",
                "remediation": "Use tempfile.NamedTemporaryFile or tempfile.mkstemp."
            },
            {
                "id": "LOW-003",
                "title": "Verbose Exception Stack Trace Output",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-209",
                "severity": "LOW",
                "cvss": 3.5,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".java"],
                "patterns": [
                    r"(?i)traceback\.print_exc\s*\(",
                    r"(?i)e\.printStackTrace\s*\(",
                    r"(?i)console\.trace\s*\("
                ],
                "description": "Printing full execution stack traces to standard output or error streams can leak internal paths and code structure.",
                "remediation": "Log structured errors with sanitized messages in production environments."
            },
            {
                "id": "LOW-004",
                "title": "Insecure Cookie Flag Configuration (Missing HttpOnly / SameSite)",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-614",
                "severity": "LOW",
                "cvss": 3.4,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".php"],
                "patterns": [
                    r"(?i)set_cookie\s*\(.*httponly\s*=\s*False",
                    r"(?i)samesite\s*=\s*['\"]none['\"]"
                ],
                "description": "Cookies set without HttpOnly or with SameSite=None are exposed to cross-site scripts and CSRF.",
                "remediation": "Enforce HttpOnly=True and SameSite=Lax/Strict on session cookies."
            },

            # =================================================================
            # 7. INFORMATIONAL FINDINGS (INFO SEVERITY)
            # =================================================================
            {
                "id": "INFO-001",
                "title": "Application Debug Mode Configured True",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-489",
                "severity": "INFO",
                "cvss": 0.0,
                "confidence": "HIGH",
                "languages": [".py", ".js", ".ts", ".json", ".env", ".yaml", ".yml"],
                "patterns": [
                    r"(?i)\bDEBUG\s*=\s*True\b",
                    r"(?i)\bAPP_DEBUG\s*=\s*true\b",
                    r"(?i)\bdebug\s*:\s*true\b"
                ],
                "description": "Debug mode is enabled, which may generate interactive debug consoles or verbose error reports.",
                "remediation": "Ensure DEBUG is set to False in production deployments."
            },
            {
                "id": "INFO-002",
                "title": "Security-Sensitive TODO / FIXME / HACK Comment",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-546",
                "severity": "INFO",
                "cvss": 0.0,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"(?i)(?:#|//|\*)\s*(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*?(?:security|auth|vuln|password|secret|sanitize|bypass|token|cve)"
                ],
                "description": "Code comment indicates pending security remediation, temporary bypass, or known incomplete logic.",
                "remediation": "Review and resolve the pending security task before releasing to production."
            },
            {
                "id": "INFO-003",
                "title": "Hardcoded Localhost / Internal IP Address Reference",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-200",
                "severity": "INFO",
                "cvss": 0.0,
                "confidence": "HIGH",
                "languages": ["all"],
                "patterns": [
                    r"(?:127\.0\.0\.1|0\.0\.0\.0|localhost:\d+)"
                ],
                "description": "Hardcoded loopback or local binding address found in configuration or code.",
                "remediation": "Use configurable environment variables for hostnames and service endpoints."
            },
            {
                "id": "INFO-004",
                "title": "Insecure Plaintext HTTP URL Protocol in Source",
                "owasp": "A02:2021-Cryptographic Failures",
                "cwe": "CWE-319",
                "severity": "INFO",
                "cvss": 0.0,
                "confidence": "MEDIUM",
                "languages": [".py", ".js", ".ts", ".html", ".env"],
                "patterns": [
                    r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas\.|w3\.org)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                ],
                "description": "Source code references unencrypted HTTP endpoints instead of HTTPS.",
                "remediation": "Update all endpoint URLs to use encrypted HTTPS protocol."
            },
            {
                "id": "INFO-005",
                "title": "Permissive CORS Access-Control-Allow-Origin Wildcard",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-942",
                "severity": "INFO",
                "cvss": 0.0,
                "confidence": "HIGH",
                "languages": [".py", ".js", ".ts", ".json", ".config"],
                "patterns": [
                    r"(?i)Access-Control-Allow-Origin\s*:\s*\*",
                    r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]"
                ],
                "description": "Public API allows cross-origin requests from any origin via wildcard.",
                "remediation": "Verify whether wildcard origin is intentional for public endpoints."
            }
        ]


class SASTScanner:
    """Enterprise Static Application Security Testing (SAST) Scanner Engine"""

    IGNORE_DIRS: Set[str] = {
        '.git', '.svn', '.hg', 'node_modules', 'venv', 'hexstrike-env',
        '__pycache__', '.pytest_cache', '.idea', '.vscode', 'dist', 'build',
        'coverage', '.next', '.nuxt', 'vendor', 'bin', 'obj'
    }

    SUPPORTED_EXTENSIONS: Set[str] = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.go',
        '.rb', '.cs', '.c', '.cpp', '.h', '.html', '.htm', '.vue',
        '.jinja', '.j2', '.env', '.yaml', '.yml', '.json', '.xml', '.config'
    }

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules or SASTRuleEngine.get_rules()
        self._compiled_rules = self._compile_rules()

    def _compile_rules(self) -> List[Dict[str, Any]]:
        compiled = []
        for r in self.rules:
            patterns = [re.compile(p) for p in r.get("patterns", [])]
            compiled.append({
                **r,
                "compiled_patterns": patterns
            })
        return compiled

    def scan_file(self, file_path: str) -> List[SASTFinding]:
        """Scan a single file for vulnerabilities"""
        findings: List[SASTFinding] = []
        path = Path(file_path)

        if not path.is_file():
            return findings

        ext = path.suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS and not path.name.startswith('.env'):
            return findings

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return findings

        for line_idx, line in enumerate(lines, start=1):
            # Skip empty lines or pure comments (basic check)
            stripped = line.strip()
            if not stripped or stripped.startswith(('#', '//', '/*', '*')):
                # Check for secrets even in comments
                is_comment = True
            else:
                is_comment = False

            for rule in self._compiled_rules:
                # Language filter check
                langs = rule.get("languages", ["all"])
                if "all" not in langs and ext not in langs:
                    continue

                # Don't skip secrets in comments if rule is secret-related
                if is_comment and not rule["id"].startswith("SEC"):
                    continue

                for pattern in rule["compiled_patterns"]:
                    match = pattern.search(line)
                    if match:
                        col_idx = match.start() + 1
                        matched_str = match.group(0)

                        # Mask sensitive secret matches for reporting safety
                        if rule["id"].startswith("SEC") and len(matched_str) > 8:
                            masked_snippet = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:]
                        else:
                            masked_snippet = matched_str

                        # Context window: +/- 2 lines
                        start_ctx = max(0, line_idx - 3)
                        end_ctx = min(len(lines), line_idx + 2)
                        context = [
                            f"{i+1:4d} | {lines[i].rstrip()}"
                            for i in range(start_ctx, end_ctx)
                        ]

                        finding = SASTFinding(
                            rule_id=rule["id"],
                            title=rule["title"],
                            severity=rule["severity"],
                            cvss_score=rule["cvss"],
                            owasp_category=rule["owasp"],
                            cwe_id=rule["cwe"],
                            file_path=str(path.resolve()),
                            line_number=line_idx,
                            column_number=col_idx,
                            matched_snippet=masked_snippet,
                            code_context=context,
                            description=rule["description"],
                            remediation=rule["remediation"],
                            confidence=rule["confidence"]
                        )
                        findings.append(finding)
                        break  # Match one pattern per rule per line

        return findings

    def scan_directory(
        self,
        target_path: str,
        ignore_dirs: Optional[Set[str]] = None,
        min_severity: Optional[str] = None,
        github_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Recursively scan a directory tree or GitHub repository for security vulnerabilities"""
        start_time = datetime.now()
        effective_ignore = self.IGNORE_DIRS.union(ignore_dirs or set())
        is_remote_repo = False
        repo_info = None
        temp_repo_path = None
        base_temp_path = None

        raw_target = (github_url or target_path or "").strip()

        # Check if the target is a remote GitHub / Git repository
        if is_git_or_github_url(raw_target):
            is_remote_repo = True
            fetch_res = fetch_or_clone_repo(raw_target)
            if not fetch_res.get("success"):
                return {
                    "success": False,
                    "target_path": raw_target,
                    "error": f"Failed to fetch remote repository: {fetch_res.get('error')}",
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
                    "target_path": raw_target,
                    "error": f"Target path '{raw_target}' does not exist locally.",
                    "findings": [],
                    "summary": {}
                }

        scanned_files_count = 0
        total_findings: List[SASTFinding] = []

        if target.is_file():
            files_to_scan = [target]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(target):
                # Filter ignored directories in-place
                dirs[:] = [d for d in dirs if d not in effective_ignore and not d.startswith('.')]
                for file_name in files:
                    ext = os.path.splitext(file_name)[1].lower()
                    if ext in self.SUPPORTED_EXTENSIONS or file_name.startswith('.env'):
                        files_to_scan.append(Path(root) / file_name)

        for file_path in files_to_scan:
            scanned_files_count += 1
            file_findings = self.scan_file(str(file_path))
            
            # Clean up display path relative to repo or scan root
            if is_remote_repo and temp_repo_path:
                try:
                    for f in file_findings:
                        rel_p = os.path.relpath(f.file_path, temp_repo_path)
                        f.file_path = rel_p.replace("\\", "/")
                except Exception:
                    pass
            total_findings.extend(file_findings)

        # Filter by minimum severity if requested
        severity_ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if min_severity and min_severity.upper() in severity_ranks:
            min_rank = severity_ranks[min_severity.upper()]
            total_findings = [f for f in total_findings if severity_ranks.get(f.severity, 0) >= min_rank]

        # Sort findings by CVSS score descending
        total_findings.sort(key=lambda x: x.cvss_score, reverse=True)

        duration_seconds = (datetime.now() - start_time).total_seconds()

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        owasp_breakdown: Dict[str, int] = {}
        for f in total_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            owasp_breakdown[f.owasp_category] = owasp_breakdown.get(f.owasp_category, 0) + 1

        # Posture Score calculation (100 base, deductions based on finding severity)
        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        # Cleanup temporary cloned repository files
        if is_remote_repo and temp_repo_path:
            cleanup_repo(temp_repo_path, base_temp_path)

        return {
            "success": True,
            "target_path": raw_target,
            "is_github_repo": is_remote_repo,
            "repository_info": repo_info,
            "scan_timestamp": datetime.now().isoformat(),
            "duration_seconds": round(duration_seconds, 3),
            "files_scanned": scanned_files_count,
            "total_findings": len(total_findings),
            "security_score": security_score,
            "severity_summary": counts,
            "owasp_summary": owasp_breakdown,
            "findings": [f.to_dict() for f in total_findings]
        }


    def generate_markdown_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate a formatted markdown audit report"""
        if not scan_results.get("success"):
            return f"### SAST Scan Failed\n\nError: {scan_results.get('error', 'Unknown error')}"

        summary = scan_results.get("severity_summary", {})
        score = scan_results.get("security_score", 100)
        target = scan_results.get("target_path", "Unknown")

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 60 else "🔴"

        md = [
            f"# 🛡️ HexStrike SAST Vulnerability Assessment Report",
            f"**Target:** `{target}` | **Scanned Files:** {scan_results.get('files_scanned', 0)} | **Duration:** {scan_results.get('duration_seconds', 0)}s",
            f"**Security Posture Score:** {status_emoji} **{score}/100**",
            "",
            "## 📊 Executive Severity Breakdown",
            f"- 🔴 **Critical:** {summary.get('CRITICAL', 0)}",
            f"- 🟠 **High:** {summary.get('HIGH', 0)}",
            f"- 🟡 **Medium:** {summary.get('MEDIUM', 0)}",
            f"- 🔵 **Low:** {summary.get('LOW', 0)}",
            f"- ⚪ **Info:** {summary.get('INFO', 0)}",
            "",
            "## 🎯 OWASP Top 10 Distribution",
        ]

        for cat, count in scan_results.get("owasp_summary", {}).items():
            md.append(f"- **{cat}:** {count} issues")

        md.append("")
        md.append("## 🔍 Detailed Findings (Prioritized by CVSS)")

        findings = scan_results.get("findings", [])
        if not findings:
            md.append("✅ *No static security vulnerabilities detected in scanned files.*")
        else:
            for idx, f in enumerate(findings[:25], start=1):
                sev_badge = f"**[{f['severity']}] (CVSS {f['cvss_score']})**"
                md.append(f"### {idx}. {f['title']} {sev_badge}")
                md.append(f"- **File:** `{f['file_path']}:{f['line_number']}`")
                md.append(f"- **OWASP / CWE:** `{f['owasp_category']}` / `{f['cwe_id']}`")
                md.append(f"- **Confidence:** `{f['confidence']}`")
                md.append(f"- **Description:** {f['description']}")
                md.append(f"- **Remediation:** {f['remediation']}")
                md.append("```")
                md.append("\n".join(f.get("code_context", [])))
                md.append("```")
                md.append("")

        return "\n".join(md)


def main():
    """Standalone CLI runner for testing the SAST scanner"""
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike SAST Code Security Scanner")
    parser.add_argument("target", help="Path to file or directory to scan")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="LOW")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    scanner = SASTScanner()
    results = scanner.scan_directory(args.target, min_severity=args.min_severity)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(scanner.generate_markdown_report(results))


if __name__ == "__main__":
    main()

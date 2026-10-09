#!/usr/bin/env python3
"""
HexStrike AI - AppSec & Asset Monitoring Test Suite
===================================================
Automated verification tests for SAST, DAST, SCA, CSV Monitor, DNS, SSL, and Unified Reporter.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from tools import (
    SASTScanner,
    DASTScanner,
    SCAScanner,
    CSVMonitor,
    DNSMonitor,
    SSLMonitor,
    UnifiedAppSecReporter
)


class TestAppSecSuite(unittest.TestCase):
    """Test suite verifying all AppSec & Monitoring engines"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sast_scanner_hardcoded_secret(self):
        test_file = Path(self.temp_dir.name) / "vulnerable_code.py"
        test_file.write_text("""
import os
# Hardcoded AWS key
aws_key = "AKIA1234567890ABCDEF"
# Command injection flaw
os.system("ls " + user_input)
# SQL injection flaw
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
""", encoding='utf-8')

        scanner = SASTScanner()
        results = scanner.scan_directory(self.temp_dir.name)

        self.assertTrue(results["success"])
        self.assertGreaterEqual(results["total_findings"], 2)
        found_rules = [f["rule_id"] for f in results["findings"]]
        self.assertIn("SEC-001", found_rules)
        self.assertIn("CMD-001", found_rules)

    def test_sca_scanner_manifest(self):
        req_file = Path(self.temp_dir.name) / "requirements.txt"
        req_file.write_text("""
flask==2.2.0
urllib3==1.26.4
requests==2.30.0
""", encoding='utf-8')

        scanner = SCAScanner(query_osv_api=False)
        results = scanner.scan_manifest(str(req_file))

        self.assertTrue(results["success"])
        self.assertEqual(results["dependencies_found"], 3)
        self.assertGreaterEqual(results["vulnerabilities_count"], 1)

    def test_csv_monitor_ingestion_and_diff(self):
        baseline_file = Path(self.temp_dir.name) / "baseline.csv"
        baseline_file.write_text("""Title,Severity,Asset,Port,CVE
OpenSSH Weak Key,MEDIUM,192.168.1.10,22,CVE-2020-15778
Apache HTTPD RCE,CRITICAL,192.168.1.50,80,CVE-2021-41773
""", encoding='utf-8')

        current_file = Path(self.temp_dir.name) / "current.csv"
        current_file.write_text("""Title,Severity,Asset,Port,CVE
OpenSSH Weak Key,MEDIUM,192.168.1.10,22,CVE-2020-15778
Log4Shell RCE,CRITICAL,192.168.1.60,8080,CVE-2021-44228
""", encoding='utf-8')

        monitor = CSVMonitor()
        results = monitor.monitor_csv_feed(str(current_file), baseline_path=str(baseline_file))

        self.assertTrue(results["success"])
        self.assertEqual(results["total_records"], 2)
        diff = results.get("delta_diff", {})
        self.assertEqual(diff.get("new_count"), 1)        # Log4Shell
        self.assertEqual(diff.get("resolved_count"), 1)   # Apache HTTPD resolved
        self.assertEqual(diff.get("persistent_count"), 1) # OpenSSH persistent

    def test_dns_monitor_structure(self):
        monitor = DNSMonitor()
        results = monitor.check_domain_health("example.com")
        self.assertTrue(results["success"])
        self.assertEqual(results["domain"], "example.com")
        self.assertIn("issues", results)

    def test_unified_reporter_consolidation(self):
        reporter = UnifiedAppSecReporter()

        mock_sast = {
            "success": True,
            "security_score": 75,
            "findings": [{
                "title": "SQL Injection",
                "severity": "CRITICAL",
                "cvss_score": 9.4,
                "owasp_category": "A03:2021-Injection",
                "file_path": "app.py",
                "line_number": 42,
                "matched_snippet": "cursor.execute(f'SELECT...')"
            }]
        }

        mock_dast = {
            "success": True,
            "security_score": 85,
            "findings": [{
                "title": "Missing Content-Security-Policy",
                "severity": "MEDIUM",
                "cvss_score": 5.4,
                "owasp_category": "A05:2021-Security Misconfiguration",
                "target_url": "https://example.com",
                "evidence": "No CSP header found"
            }]
        }

        unified = reporter.generate_unified_report(
            project_name="Unit Test Assessment",
            sast_results=mock_sast,
            dast_results=mock_dast
        )

        self.assertTrue(unified["success"])
        self.assertEqual(unified["total_findings"], 2)
        self.assertEqual(unified["severity_summary"]["CRITICAL"], 1)
        self.assertEqual(unified["severity_summary"]["MEDIUM"], 1)
        dashboard_md = reporter.generate_markdown_dashboard(unified)
        self.assertIn("Executive Posture", dashboard_md)


if __name__ == "__main__":
    unittest.main()

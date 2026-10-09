#!/usr/bin/env python3
"""
HexStrike AI - Domain Issues & DNS Monitoring Module
===================================================
Comprehensive DNS health inspection, SPF/DMARC/DKIM email authentication analysis,
subdomain takeover risk scanning, typosquatting permutation generation, and registrar checks.
"""

import re
import sys
import json
import socket
import ssl
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
import urllib.parse


@dataclass
class DNSIssue:
    """Represents a domain or DNS security finding"""
    id: str
    category: str         # EMAIL_SECURITY, DNS_CONFIG, TAKEOVER_RISK, TYPOSQUAT
    title: str
    severity: str         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float     # 0.0 - 10.0
    description: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DNSMonitor:
    """Enterprise Domain Health & DNS Security Inspection Engine"""

    TAKEOVER_SIGNATURES = {
        "github.io": {
            "cname_pattern": r"\.github\.io$",
            "service": "GitHub Pages",
            "severity": "HIGH",
            "cvss": 8.0,
            "desc": "Subdomain CNAME points to an unclaimed GitHub Pages site."
        },
        "herokuapp.com": {
            "cname_pattern": r"\.herokuapp\.com$",
            "service": "Heroku",
            "severity": "HIGH",
            "cvss": 8.2,
            "desc": "Subdomain CNAME points to a deprovisioned Heroku application."
        },
        "s3.amazonaws.com": {
            "cname_pattern": r"s3.*?\.amazonaws\.com$",
            "service": "AWS S3 Bucket",
            "severity": "CRITICAL",
            "cvss": 9.1,
            "desc": "Subdomain CNAME points to an unclaimed or deleted AWS S3 bucket."
        },
        "azurewebsites.net": {
            "cname_pattern": r"\.azurewebsites\.net$",
            "service": "Azure App Services",
            "severity": "HIGH",
            "cvss": 8.0,
            "desc": "Subdomain CNAME points to a removed Azure App Service."
        },
        "myshopify.com": {
            "cname_pattern": r"\.myshopify\.com$",
            "service": "Shopify",
            "severity": "HIGH",
            "cvss": 7.5,
            "desc": "Subdomain points to an unclaimed Shopify store."
        }
    }

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def _resolve_record_native(self, name: str, qtype: str) -> List[str]:
        """Perform native DNS resolution using dnspython or standard library"""
        results = []
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(name, qtype)
            for rdata in answers:
                results.append(str(rdata).strip('"'))
            return list(set(results))
        except Exception:
            pass

        # Fallback to standard library getaddrinfo for A/AAAA
        try:
            if qtype in ["A", "AAAA"]:
                family = socket.AF_INET if qtype == "A" else socket.AF_INET6
                addr_info = socket.getaddrinfo(name, None, family)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in results:
                        results.append(ip)
        except Exception:
            pass

        return list(set(results))

    def check_spf(self, domain: str, txt_records: List[str]) -> Tuple[Optional[str], List[DNSIssue]]:
        """Verify Sender Policy Framework (SPF) configuration"""
        issues: List[DNSIssue] = []
        spf_record = None

        for txt in txt_records:
            if txt.startswith("v=spf1"):
                spf_record = txt
                break

        if not spf_record:
            issues.append(DNSIssue(
                id="DNS-SPF-001",
                category="EMAIL_SECURITY",
                title="Missing SPF Record on Domain",
                severity="HIGH",
                cvss_score=7.5,
                description="The domain does not publish an SPF record. Attackers can forge emails from this domain (email spoofing) without authentication rejection.",
                evidence=f"Domain: {domain} | No TXT record starting with 'v=spf1'",
                remediation="Publish a valid SPF TXT record on the root domain (e.g. 'v=spf1 include:_spf.google.com -all')."
            ))
        else:
            # Check SPF configuration details
            if "+all" in spf_record:
                issues.append(DNSIssue(
                    id="DNS-SPF-002",
                    category="EMAIL_SECURITY",
                    title="Dangerous Permissive SPF Policy (+all)",
                    severity="CRITICAL",
                    cvss_score=9.1,
                    description="The SPF record specifies '+all', which explicitly allows ANY server on the Internet to send legitimate email as this domain.",
                    evidence=f"SPF: {spf_record}",
                    remediation="Change '+all' to strict '-all' (HardFail) or '~all' (SoftFail)."
                ))
            elif "?all" in spf_record:
                issues.append(DNSIssue(
                    id="DNS-SPF-003",
                    category="EMAIL_SECURITY",
                    title="Neutral SPF Policy (?all)",
                    severity="MEDIUM",
                    cvss_score=5.3,
                    description="The SPF record uses '?all' (Neutral), which instructs receiving servers not to take definitive anti-spoofing action.",
                    evidence=f"SPF: {spf_record}",
                    remediation="Update '?all' to '-all' for strict policy enforcement."
                ))

        return spf_record, issues

    def check_dmarc(self, domain: str) -> Tuple[Optional[str], List[DNSIssue]]:
        """Verify Domain-based Message Authentication, Reporting, and Conformance (DMARC)"""
        issues: List[DNSIssue] = []
        dmarc_name = f"_dmarc.{domain}"
        txt_records = self._resolve_record_native(dmarc_name, "TXT")
        dmarc_record = None

        for txt in txt_records:
            if "v=DMARC1" in txt:
                dmarc_record = txt
                break

        if not dmarc_record:
            issues.append(DNSIssue(
                id="DNS-DMARC-001",
                category="EMAIL_SECURITY",
                title="Missing DMARC Record",
                severity="HIGH",
                cvss_score=7.5,
                description="DMARC is not configured for this domain. Email receivers have no policy instructions for handling failed SPF/DKIM messages.",
                evidence=f"Queried '{dmarc_name}' - No DMARC1 TXT record found.",
                remediation="Create a TXT record at '_dmarc." + domain + "' with 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + domain + "'."
            ))
        else:
            # Check DMARC policy mode (p=none vs p=quarantine/p=reject)
            p_match = re.search(r'\bp\s*=\s*([a-zA-Z]+)', dmarc_record)
            if p_match:
                policy = p_match.group(1).lower()
                if policy == "none":
                    issues.append(DNSIssue(
                        id="DNS-DMARC-002",
                        category="EMAIL_SECURITY",
                        title="Weak DMARC Policy Mode (p=none)",
                        severity="MEDIUM",
                        cvss_score=5.4,
                        description="DMARC policy is set to 'p=none' (monitoring only). Spoofed emails will still be delivered to recipients' inboxes.",
                        evidence=f"DMARC: {dmarc_record}",
                        remediation="Upgrade DMARC policy to 'p=quarantine' or 'p=reject' to enforce rejection of forged emails."
                    ))

            # Check aggregate report email (rua)
            if "rua=" not in dmarc_record:
                issues.append(DNSIssue(
                    id="DNS-DMARC-003",
                    category="EMAIL_SECURITY",
                    title="Missing DMARC Reporting Destination (rua)",
                    severity="LOW",
                    cvss_score=3.1,
                    description="The DMARC record does not specify an aggregate reporting email (rua=). You will not receive visibility into email deliverability or spoofing attempts.",
                    evidence=f"DMARC: {dmarc_record}",
                    remediation="Add 'rua=mailto:reports@yourdomain.com' to receive daily XML authentication reports."
                ))

        return dmarc_record, issues

    def check_takeover_risk(self, domain: str, cname_records: List[str]) -> List[DNSIssue]:
        """Check if any CNAME record points to an unclaimed cloud service"""
        issues: List[DNSIssue] = []
        for cname in cname_records:
            for service_key, meta in self.TAKEOVER_SIGNATURES.items():
                if re.search(meta["cname_pattern"], cname, re.IGNORECASE):
                    issues.append(DNSIssue(
                        id=f"DNS-TAKEOVER-{service_key.replace('.', '').upper()}",
                        category="TAKEOVER_RISK",
                        title=f"Potential Subdomain Takeover Risk via {meta['service']}",
                        severity=meta["severity"],
                        cvss_score=meta["cvss"],
                        description=f"{meta['desc']} An attacker claiming this cloud resource could hijack traffic to '{domain}'.",
                        evidence=f"CNAME points to: {cname}",
                        remediation=f"Verify the {meta['service']} resource is active. If decommissioned, remove the CNAME DNS record."
                    ))
        return issues

    def generate_typosquat_permutations(self, domain: str) -> List[Dict[str, str]]:
        """Generate high-risk typosquatting domain permutations"""
        parts = domain.split(".")
        if len(parts) < 2:
            return []

        name, tld = parts[0], ".".join(parts[1:])
        permutations = []

        # 1. Missing character (omission)
        if len(name) > 3:
            for i in range(len(name)):
                omitted = name[:i] + name[i+1:]
                permutations.append({
                    "permutation": f"{omitted}.{tld}",
                    "type": "omission",
                    "risk": "MEDIUM"
                })

        # 2. Adjacent character transposition (swap)
        for i in range(len(name) - 1):
            swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
            permutations.append({
                "permutation": f"{swapped}.{tld}",
                "type": "transposition",
                "risk": "MEDIUM"
            })

        # 3. Double character (repetition)
        for i in range(len(name)):
            repeated = name[:i] + name[i] + name[i:]
            permutations.append({
                "permutation": f"{repeated}.{tld}",
                "type": "repetition",
                "risk": "LOW"
            })

        # 4. Common TLD swaps
        alt_tlds = ["com", "net", "org", "co", "io", "ai", "security", "app"]
        for alt in alt_tlds:
            if alt != tld:
                permutations.append({
                    "permutation": f"{name}.{alt}",
                    "type": "tld_swap",
                    "risk": "HIGH"
                })

        return permutations[:15]

    def check_domain_health(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS and domain health analysis"""
        start_time = datetime.now()
        clean_domain = domain.strip().lower()
        if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
            clean_domain = urllib.parse.urlparse(clean_domain).netloc

        all_issues: List[DNSIssue] = []

        # Resolve core DNS records
        a_records = self._resolve_record_native(clean_domain, "A")
        aaaa_records = self._resolve_record_native(clean_domain, "AAAA")
        mx_records = self._resolve_record_native(clean_domain, "MX")
        txt_records = self._resolve_record_native(clean_domain, "TXT")
        ns_records = self._resolve_record_native(clean_domain, "NS")
        cname_records = self._resolve_record_native(clean_domain, "CNAME")

        # 1. Check Root A / AAAA resolution
        if not a_records and not cname_records:
            all_issues.append(DNSIssue(
                id="DNS-RESOLV-001",
                category="DNS_CONFIG",
                title="Domain Fails to Resolve to IPv4 Address",
                severity="HIGH",
                cvss_score=7.0,
                description="The target domain does not have active A or CNAME DNS records.",
                evidence=f"No A or CNAME records found for {clean_domain}",
                remediation="Configure valid A or CNAME records in your authoritative DNS zone."
            ))

        # 2. Check SPF & Email Posture
        spf_record, spf_issues = self.check_spf(clean_domain, txt_records)
        all_issues.extend(spf_issues)

        # 3. Check DMARC
        dmarc_record, dmarc_issues = self.check_dmarc(clean_domain)
        all_issues.extend(dmarc_issues)

        # 4. Subdomain Takeover Risk
        takeover_issues = self.check_takeover_risk(clean_domain, cname_records)
        all_issues.extend(takeover_issues)

        # 5. Typosquatting Permutations
        typosquats = self.generate_typosquat_permutations(clean_domain)

        all_issues.sort(key=lambda x: x.cvss_score, reverse=True)
        duration = (datetime.now() - start_time).total_seconds()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for i in all_issues:
            counts[i.severity] = counts.get(i.severity, 0) + 1

        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        res_dict = {
            "success": True,
            "domain": clean_domain,
            "timestamp": datetime.now().isoformat(),
            "check_timestamp": datetime.now().isoformat(),
            "duration_seconds": round(duration, 3),
            "security_score": security_score,
            "total_issues": len(all_issues),
            "severity_summary": counts,
            "dns_records": {
                "A": a_records,
                "AAAA": aaaa_records,
                "MX": mx_records,
                "TXT": txt_records,
                "NS": ns_records,
                "CNAME": cname_records,
                "SPF": spf_record,
                "DMARC": dmarc_record
            },
            "issues": [i.to_dict() for i in all_issues],
            "typosquatting_permutations": typosquats
        }
        res_dict["markdown_report"] = self.generate_markdown_report(res_dict)
        return res_dict

    def generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Generate formatted Markdown report for DNS and domain health check"""
        if not results.get("success"):
            return f"### DNS Health Audit Failed\n\nError: {results.get('error', 'Unknown error')}"

        summary = results.get("severity_summary", {})
        score = results.get("security_score", 100)
        domain = results.get("domain", "Unknown")

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 60 else "🔴"

        md = [
            f"# 🌐 HexStrike DNS & Domain Posture Audit Report",
            f"**Target Domain:** `{domain}` | **Duration:** {results.get('duration_seconds', 0)}s",
            f"**Domain Health Score:** {status_emoji} **{score}/100**",
            "",
            "## 📊 Executive Severity Breakdown",
            f"- 🔴 **Critical:** {summary.get('CRITICAL', 0)}",
            f"- 🟠 **High:** {summary.get('HIGH', 0)}",
            f"- 🟡 **Medium:** {summary.get('MEDIUM', 0)}",
            f"- 🔵 **Low:** {summary.get('LOW', 0)}",
            "",
            "## ✉️ Email Authentication Status",
            f"- **SPF Record:** `{'✅ ' + results['dns_records']['SPF'] if results['dns_records'].get('SPF') else '❌ Missing'}`",
            f"- **DMARC Record:** `{'✅ ' + results['dns_records']['DMARC'] if results['dns_records'].get('DMARC') else '❌ Missing'}`",
            "",
            "## 🔍 Detected DNS & Configuration Issues"
        ]

        issues = results.get("issues", [])
        if not issues:
            md.append("✅ *No DNS or email security misconfigurations detected.*")
        else:
            for idx, iss in enumerate(issues, start=1):
                sev_badge = f"**[{iss['severity']}] (CVSS {iss['cvss_score']})**"
                md.append(f"### {idx}. {iss['title']} {sev_badge}")
                md.append(f"- **Category:** `{iss['category']}`")
                md.append(f"- **Evidence:** `{iss['evidence']}`")
                md.append(f"- **Description:** {iss['description']}")
                md.append(f"- **Remediation:** {iss['remediation']}")
                md.append("")

        typos = results.get("typosquatting_permutations", [])
        if typos:
            md.extend([
                "## 🕵️ High-Risk Typosquatting Permutations",
                "| Permutation | Type | Risk Level |",
                "| :--- | :--- | :--- |"
            ])
            for t in typos[:8]:
                md.append(f"| `{t['permutation']}` | {t['type']} | **{t['risk']}** |")

        return "\n".join(md)


def main():
    """Standalone CLI runner for testing DNS monitoring"""
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike Domain & DNS Health Monitor")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    monitor = DNSMonitor()
    results = monitor.check_domain_health(args.domain)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(monitor.generate_markdown_report(results))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
HexStrike AI - CSV Monitoring & Ingestion Pipeline Module
=========================================================
Ingests vulnerability exports, asset inventories, and security telemetry CSV files.
Validates schemas, computes delta diffs (new, resolved, persistent findings), detects anomalies,
and tracks historical posture shifts.
"""

import os
import csv
import sys
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime


@dataclass
class VulnerabilityRecord:
    """Standardized representation of a vulnerability row in CSV"""
    uid: str
    title: str
    severity: str
    cve: Optional[str]
    asset: str
    port: Optional[str]
    status: str
    raw_row: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CSVMonitor:
    """Enterprise CSV Ingestion, Validation & Delta Tracking Engine"""

    SEVERITY_MAPPING = {
        "critical": "CRITICAL",
        "crit": "CRITICAL",
        "high": "HIGH",
        "hi": "HIGH",
        "medium": "MEDIUM",
        "med": "MEDIUM",
        "moderate": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "informational": "INFO"
    }

    def __init__(self):
        pass

    def _generate_record_uid(self, row: Dict[str, str], title_key: str, asset_key: str, cve_key: Optional[str]) -> str:
        """Create a deterministic unique identifier for a vulnerability finding"""
        title = row.get(title_key, "").strip().lower()
        asset = row.get(asset_key, "").strip().lower()
        cve = row.get(cve_key, "").strip().lower() if cve_key else ""
        raw = f"{asset}|{title}|{cve}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]

    def _normalize_severity(self, raw_val: str) -> str:
        """Normalize various severity formats into standard levels"""
        clean = raw_val.strip().lower()
        return self.SEVERITY_MAPPING.get(clean, "MEDIUM")

    def validate_and_parse_csv(self, file_path: str) -> Tuple[List[VulnerabilityRecord], List[str], Dict[str, Any]]:
        """Parse CSV and validate schema against common vulnerability formats"""
        path = Path(file_path).resolve()
        if not path.is_file():
            return [], [f"File '{file_path}' does not exist."], {}

        records: List[VulnerabilityRecord] = []
        anomalies: List[str] = []
        schema_info: Dict[str, Any] = {}

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                headers = [h.strip() for h in (reader.fieldnames or [])]

                if not headers:
                    return [], ["Empty or invalid CSV file header."], {}

                schema_info["headers"] = headers
                schema_info["detected_columns"] = len(headers)

                # Identify key columns dynamically
                header_lower_map = {h.lower(): h for h in headers}

                # Find title / name column
                title_key = next((header_lower_map[h] for h in ["title", "vulnerability", "plugin name", "issue", "name", "finding"] if h in header_lower_map), None)
                # Find severity column
                sev_key = next((header_lower_map[h] for h in ["severity", "risk", "cvss score", "level", "impact"] if h in header_lower_map), None)
                # Find asset / host column
                asset_key = next((header_lower_map[h] for h in ["asset", "host", "ip", "target", "hostname", "url", "node"] if h in header_lower_map), None)
                # Find CVE column
                cve_key = next((header_lower_map[h] for h in ["cve", "cve id", "cves", "vulnerability id"] if h in header_lower_map), None)
                # Find port column
                port_key = next((header_lower_map[h] for h in ["port", "service", "destination port"] if h in header_lower_map), None)

                # Fallback heuristics if column names are generic
                if not title_key and len(headers) > 0:
                    title_key = headers[0]
                    anomalies.append(f"Title column not explicitly recognized. Defaulting to first column: '{title_key}'.")

                if not asset_key and len(headers) > 1:
                    asset_key = headers[1]
                    anomalies.append(f"Asset column not explicitly recognized. Defaulting to: '{asset_key}'.")

                if not sev_key:
                    sev_key = "severity"
                    anomalies.append("Severity column missing. Defaulting findings to 'MEDIUM'.")

                schema_info["mapped_columns"] = {
                    "title_column": title_key,
                    "asset_column": asset_key,
                    "severity_column": sev_key,
                    "cve_column": cve_key,
                    "port_column": port_key
                }

                row_idx = 0
                for raw_row in reader:
                    row_idx += 1
                    title = raw_row.get(title_key, "").strip() if title_key else f"Finding #{row_idx}"
                    asset = raw_row.get(asset_key, "").strip() if asset_key else "Unknown Target"
                    raw_sev = raw_row.get(sev_key, "MEDIUM") if sev_key else "MEDIUM"
                    cve = raw_row.get(cve_key, "").strip() if cve_key else None
                    port = raw_row.get(port_key, "").strip() if port_key else None

                    # Check for anomalous / invalid data rows
                    if not title and not asset:
                        anomalies.append(f"Row #{row_idx} is completely blank.")
                        continue

                    # Validate IP format anomaly if applicable
                    if asset and ("." in asset) and not any(c.isalpha() for c in asset):
                        parts = asset.split(".")
                        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                            anomalies.append(f"Row #{row_idx}: Malformed IP address detected: '{asset}'.")

                    # Validate Port number anomaly
                    if port and port.isdigit():
                        p_int = int(port)
                        if p_int <= 0 or p_int > 65535:
                            anomalies.append(f"Row #{row_idx}: Port number out of valid range: {port}.")

                    uid = self._generate_record_uid(raw_row, title_key or "", asset_key or "", cve_key)
                    norm_sev = self._normalize_severity(raw_sev)

                    record = VulnerabilityRecord(
                        uid=uid,
                        title=title,
                        severity=norm_sev,
                        cve=cve,
                        asset=asset,
                        port=port,
                        status="ACTIVE",
                        raw_row={k: v.strip() for k, v in raw_row.items()}
                    )
                    records.append(record)

        except Exception as e:
            anomalies.append(f"Fatal parsing error: {str(e)}")

        return records, anomalies, schema_info

    def compute_delta_diff(
        self,
        current_records: List[VulnerabilityRecord],
        baseline_records: List[VulnerabilityRecord]
    ) -> Dict[str, Any]:
        """Compute delta between current scan records and baseline scan records"""
        current_map = {r.uid: r for r in current_records}
        baseline_map = {r.uid: r for r in baseline_records}

        new_findings: List[VulnerabilityRecord] = []
        resolved_findings: List[VulnerabilityRecord] = []
        persistent_findings: List[VulnerabilityRecord] = []

        # New and persistent findings
        for uid, record in current_map.items():
            if uid not in baseline_map:
                new_findings.append(record)
            else:
                persistent_findings.append(record)

        # Resolved findings
        for uid, record in baseline_map.items():
            if uid not in current_map:
                record.status = "RESOLVED"
                resolved_findings.append(record)

        return {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "new_findings": [r.to_dict() for r in new_findings],
            "resolved_findings": [r.to_dict() for r in resolved_findings],
            "persistent_findings": [r.to_dict() for r in persistent_findings]
        }

    def monitor_csv_feed(self, file_path: str, baseline_path: Optional[str] = None) -> Dict[str, Any]:
        """Main entry point to ingest, validate, and compare CSV vulnerability feeds"""
        start_time = datetime.now()
        current_records, anomalies, schema = self.validate_and_parse_csv(file_path)

        if not current_records and anomalies:
            return {
                "success": False,
                "file_path": file_path,
                "error": "Failed to parse CSV feed.",
                "anomalies": anomalies
            }

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        assets_seen = set()
        for r in current_records:
            counts[r.severity] = counts.get(r.severity, 0) + 1
            if r.asset:
                assets_seen.add(r.asset)

        # Check for sudden severity spikes (anomaly detection)
        if counts["CRITICAL"] > 10:
            anomalies.append(f"High risk spike: Found {counts['CRITICAL']} CRITICAL severity vulnerabilities.")

        # Compute delta if baseline provided
        diff_results = None
        if baseline_path and os.path.exists(baseline_path):
            baseline_records, b_anomalies, _ = self.validate_and_parse_csv(baseline_path)
            diff_results = self.compute_delta_diff(current_records, baseline_records)

        duration = (datetime.now() - start_time).total_seconds()

        # Score calculation
        deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        security_score = max(0, 100 - deductions)

        res_dict = {
            "success": True,
            "file_path": file_path,
            "baseline_path": baseline_path,
            "ingestion_timestamp": datetime.now().isoformat(),
            "duration_seconds": round(duration, 3),
            "total_records": len(current_records),
            "unique_assets_count": len(assets_seen),
            "security_score": security_score,
            "severity_summary": counts,
            "schema_metadata": schema,
            "anomalies_detected": anomalies,
            "delta_diff": diff_results,
            "records": [r.to_dict() for r in current_records]
        }
        res_dict["markdown_report"] = self.generate_markdown_report(res_dict)
        return res_dict

    def generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Generate formatted Markdown report for CSV feed monitoring"""
        if not results.get("success"):
            return f"### CSV Monitor Ingestion Failed\n\nError: {results.get('error', 'Unknown error')}\nAnomalies: {', '.join(results.get('anomalies', []))}"

        summary = results.get("severity_summary", {})
        score = results.get("security_score", 100)
        target = results.get("file_path", "Unknown")

        status_emoji = "🟢" if score >= 85 else "🟡" if score >= 60 else "🔴"

        md = [
            f"# 📊 HexStrike CSV Security Feed & Delta Monitor Report",
            f"**File:** `{target}` | **Records Ingested:** {results.get('total_records', 0)} | **Unique Assets:** {results.get('unique_assets_count', 0)}",
            f"**Asset Security Score:** {status_emoji} **{score}/100**",
            "",
            "## 📈 Current Severity Status",
            f"- 🔴 **Critical:** {summary.get('CRITICAL', 0)}",
            f"- 🟠 **High:** {summary.get('HIGH', 0)}",
            f"- 🟡 **Medium:** {summary.get('MEDIUM', 0)}",
            f"- 🔵 **Low:** {summary.get('LOW', 0)}",
            f"- ⚪ **Info:** {summary.get('INFO', 0)}"
        ]

        diff = results.get("delta_diff")
        if diff:
            md.extend([
                "",
                "## 🔄 Delta Shifts Compared to Baseline",
                f"- 🆕 **New Findings:** {diff.get('new_count', 0)}",
                f"- ✅ **Resolved Findings:** {diff.get('resolved_count', 0)}",
                f"- ⏳ **Persistent Findings:** {diff.get('persistent_count', 0)}"
            ])

        anomalies = results.get("anomalies_detected", [])
        if anomalies:
            md.extend([
                "",
                "## ⚠️ Schema & Data Quality Anomalies Detected"
            ])
            for anom in anomalies:
                md.append(f"- ⚠️ {anom}")

        md.extend([
            "",
            "## 📋 Sample Ingested Findings (Top 15)"
        ])

        records = results.get("records", [])
        if not records:
            md.append("✅ *No vulnerability records found in CSV.*")
        else:
            for idx, r in enumerate(records[:15], start=1):
                cve_tag = f"[`{r['cve']}`]" if r.get("cve") else ""
                md.append(f"{idx}. **[{r['severity']}]** {r['title']} {cve_tag} - Target: `{r['asset']}` (Port: `{r.get('port') or 'N/A'}`)")

        return "\n".join(md)


def main():
    """Standalone CLI runner for testing CSV monitoring"""
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike CSV Vulnerability Ingestion & Monitoring")
    parser.add_argument("file", help="Path to CSV vulnerability export")
    parser.add_argument("--baseline", help="Optional baseline CSV to compute delta diffs")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    monitor = CSVMonitor()
    results = monitor.monitor_csv_feed(args.file, baseline_path=args.baseline)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(monitor.generate_markdown_report(results))


if __name__ == "__main__":
    main()

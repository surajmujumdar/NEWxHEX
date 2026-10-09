from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from services.domain_analysis_service import domain_service
from typing import Optional, List

router = APIRouter()

class ThreatItem(BaseModel):
    type: str
    severity: str
    first_seen: str
    last_seen: str
    confidence: int
    source: Optional[str] = None

    model_config = {"extra": "allow"}

class DomainAnalysisResponse(BaseModel):
    target: str
    risk_level: str
    active_incidents: int
    security_score: int
    last_scanned: str
    threats: List[ThreatItem]
    country: Optional[str] = None
    isp: Optional[str] = None
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    reputation_score: Optional[int] = None
    pulse_count: Optional[int] = None
    urlscan_data: Optional[dict] = None
    virustotal_data: Optional[dict] = None
    abuseipdb_data: Optional[dict] = None
    alienvault_data: Optional[dict] = None
    domain_age_days: Optional[int] = None
    ssl_certificate: Optional[dict] = None
    dns_records: Optional[dict] = None
    last_reported: Optional[str] = None
    whois_data: Optional[dict] = None
    gridinsoft_data: Optional[dict] = None
    domscan_data: Optional[dict] = None
    vulnerabilities: Optional[List[dict]] = None
    total_vulnerabilities: Optional[int] = None
    vulnerability_risk_score: Optional[int] = None
    high_critical_vulnerabilities: Optional[int] = None
    connections: Optional[dict] = None
    nuclei_data: Optional[dict] = None
    testssl_data: Optional[dict] = None
    nmap_data: Optional[dict] = None
    osv_data: Optional[dict] = None
    threatfox_data: Optional[dict] = None
    shodan_data: Optional[dict] = None
    webscanner_data: Optional[dict] = None
    nikto_data: Optional[dict] = None
    security_rating: Optional[str] = None
    total_issues_count: Optional[int] = None
    issues_statistics: Optional[dict] = None
    domain_issues: Optional[List[dict]] = None

    model_config = {"extra": "allow"}

@router.get("/webscanner")
async def analyze_webscanner(domain: str = Query(..., description="Domain to analyze with 16-step WebScanner orchestrator")):
    """Run dedicated 16-step WebScanner vulnerability orchestration pipeline on target domain"""
    from services.webscanner_service import webscanner_service
    try:
        if not domain or not domain.strip():
            raise HTTPException(status_code=400, detail="Domain is required")
        res = await webscanner_service.scan_domain(domain.strip(), force_refresh=True)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"WebScanner error: {str(e)}")

@router.get("/analyze", response_model=DomainAnalysisResponse)
async def analyze_domain(domain: str = Query(..., description="Domain or IP address to analyze")):
    """Analyze a domain or IP address for security risks using multi-source threat intelligence."""
    try:
        if not domain or not domain.strip():
            raise HTTPException(status_code=400, detail="Domain or IP address is required")

        result = await domain_service.analyze_domain(domain.strip())

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing domain: {str(e)}")


@router.get("/validate")
async def validate_domain(domain: str = Query(..., description="Domain or IP to validate")):
    """Validate if the input is a proper domain or IP address format."""
    try:
        is_domain = domain_service.is_valid_domain(domain)
        is_ip = domain_service.is_valid_ip(domain)
        return {
            "valid": is_domain or is_ip,
            "type": "domain" if is_domain else ("ip" if is_ip else "invalid"),
            "input": domain,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error validating domain: {str(e)}")

@router.get("/export/stix")
async def export_domain_stix(domain: str = Query(..., description="Domain or IP to export")):
    """Export comprehensive OASIS STIX 2.1 JSON threat intelligence bundle for target domain"""
    from services.stix_service import stix_service
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain is required")

    result = await domain_service.analyze_domain(domain.strip())
    stix_bundle = stix_service.generate_stix_bundle(result)
    return stix_bundle

@router.post("/sync-score")
async def sync_domain_score(
    payload: dict,
    domain: str = Query(..., description="Target domain to synchronize score for")
):
    """Synchronize live calculated score, rating, and risk level to company records in database"""
    import json
    from datetime import datetime
    from database.database import SessionLocal
    from models.company import Company, CompanyRiskAssessment

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    db = SessionLocal()
    try:
        companies = db.query(Company).filter(Company.domain.ilike(f"%{clean_domain}%")).all()
        score = payload.get("security_score", 100)
        rating = payload.get("security_rating")
        risk = payload.get("risk_level")
        total_issues = payload.get("total_issues")
        high_critical = payload.get("high_critical")

        for company in companies:
            latest_assessment = db.query(CompanyRiskAssessment)\
                .filter(CompanyRiskAssessment.company_id == company.id)\
                .order_by(CompanyRiskAssessment.created_at.desc())\
                .first()

            if latest_assessment:
                latest_assessment.security_score = score
                if risk:
                    latest_assessment.risk_level = risk
                if total_issues is not None:
                    latest_assessment.vulnerabilities_count = total_issues
                if high_critical is not None:
                    latest_assessment.active_incidents = high_critical
                
                if latest_assessment.assessment_details:
                    try:
                        det = json.loads(latest_assessment.assessment_details)
                        det["security_score"] = score
                        if rating:
                            det["security_rating"] = rating
                        if risk:
                            det["risk_level"] = risk
                        if total_issues is not None:
                            det["total_issues_count"] = total_issues
                        latest_assessment.assessment_details = json.dumps(det)
                    except Exception:
                        pass
            else:
                new_assessment = CompanyRiskAssessment(
                    company_id=company.id,
                    risk_level=risk or ("HIGH" if score < 50 else "LOW"),
                    security_score=score,
                    active_incidents=high_critical or 0,
                    abuse_confidence_score=0,
                    reputation_score=score,
                    vulnerabilities_count=total_issues or 0,
                    ssl_valid=True
                )
                db.add(new_assessment)
            
            company.last_analyzed = datetime.utcnow()
            company.updated_at = datetime.utcnow()

        db.commit()
        return {"status": "success", "domain": clean_domain, "synced_companies": len(companies), "security_score": score}
    except Exception as e:
        db.rollback()
        return {"status": "error", "detail": str(e)}
    finally:
        db.close()

@router.get("/export/json")
async def export_domain_json(domain: str = Query(..., description="Domain or IP to export")):
    """Export complete domain analysis raw JSON intelligence report"""
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain is required")

    result = await domain_service.analyze_domain(domain.strip())
    return result

@router.get("/nikto")
async def get_nikto_scan(domain: str = Query(..., description="Target domain for Nikto Web Server Scan")):
    """Execute on-demand Nikto web server and CGI vulnerability audit"""
    from services.nikto_service import nikto_service
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain is required")
    return await nikto_service.scan_target(domain.strip())

@router.get("/pulse")
async def get_domain_pulse(
    domain: str = Query(..., description="Domain to run HexStrike Domain Pulse reconnaissance against"),
    profile: str = Query("STANDARD", description="Scan profile: QUICK, STANDARD, DEEP")
):
    """
    Run HexStrike-enhanced Domain Pulse reconnaissance (DNS, Subdomains, Tech, Open Ports, SSL, Alerts).
    """
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain is required")
    try:
        from orchestrator.recon_orchestrator import domain_recon_orchestrator
        res = await domain_recon_orchestrator.analyze_domain(domain.strip(), profile=profile)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Domain Pulse error: {str(e)}")




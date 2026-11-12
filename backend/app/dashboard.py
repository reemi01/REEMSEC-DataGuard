
from datetime import datetime, timedelta, timezone
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Scan, Finding
from app.permissions import require_any_authenticated_user


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


def get_risk_level(severity_summary):
    critical = severity_summary["critical"]
    high = severity_summary["high"]
    medium = severity_summary["medium"]
    low = severity_summary["low"]

    risk_score = min(
        100,
        (critical * 25) +
        (high * 15) +
        (medium * 7) +
        (low * 2),
    )

    if risk_score >= 75:
        level = "critical"
    elif risk_score >= 50:
        level = "high"
    elif risk_score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "score": risk_score,
        "level": level,
    }


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated_user),
):
    scans_query = db.query(Scan)

    if current_user.role == "employee":
        scans_query = scans_query.filter(
            Scan.user_id == current_user.id
        )

    total_scans = scans_query.count()

    findings_query = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
    )

    if current_user.role == "employee":
        findings_query = findings_query.filter(
            Scan.user_id == current_user.id
        )

    total_findings = findings_query.count()

    severity_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for severity in severity_summary:
        severity_summary[severity] = (
            findings_query
            .filter(Finding.severity == severity)
            .count()
        )

    # Last 30 days
    thirty_days_ago = (
        datetime.now(timezone.utc) - timedelta(days=30)
    )

    scans_last_30_days = scans_query.filter(
        Scan.created_at >= thirty_days_ago
    ).count()

    # Last 7 days
    seven_days_ago = (
        datetime.now(timezone.utc) - timedelta(days=7)
    )

    scans_last_7_days = scans_query.filter(
        Scan.created_at >= seven_days_ago
    ).count()

    # Recent scans
    recent_scans = (
        scans_query
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )

    recent_scans_data = [
        {
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "status": scan.status,
            "total_findings": scan.total_findings,
            "severity_summary": scan.severity_summary,
            "scanned_files": scan.scanned_files,
            "skipped_files": scan.skipped_files,
            "created_at": scan.created_at,
        }
        for scan in recent_scans
    ]

    # Scan type distribution
    scan_types = Counter(
        scan_type[0]
        for scan_type in (
            scans_query.with_entities(Scan.scan_type)
            .all()
        )
    )

    scan_type_distribution = dict(scan_types)

    # Most frequently detected rules
    top_rules_query = (
        findings_query
        .with_entities(
            Finding.rule,
        )
        .all()
    )

    rule_counts = Counter(
        item.rule for item in top_rules_query
    )

    top_rules = [
        {
            "rule": rule,
            "count": count,
        }
        for rule, count in rule_counts.most_common(5)
    ]

    risk_assessment = get_risk_level(severity_summary)

    response = {
        "role": current_user.role,
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_summary": severity_summary,
        "risk_assessment": risk_assessment,
        "scans_last_7_days": scans_last_7_days,
        "scans_last_30_days": scans_last_30_days,
        "scan_type_distribution": scan_type_distribution,
        "recent_scans": recent_scans_data,
        "top_detected_rules": top_rules,
    }

    if current_user.role in [
        "admin",
        "security_analyst",
    ]:
        response["total_users"] = db.query(User).count()

        response["active_users"] = (
            db.query(User)
            .filter(User.is_active.is_(True))
            .count()
        )

    return response

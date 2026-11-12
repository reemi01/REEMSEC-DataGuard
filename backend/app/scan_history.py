
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import User, Scan
from app.permissions import require_any_authenticated_user, require_admin
from app.services.audit_service import log_action


router = APIRouter(
    prefix="/scans",
    tags=["Scan History"]
)


# Format Individual Finding
def format_finding(finding):
    return {
        "id": finding.id,
        "rule": finding.rule,
        "severity": finding.severity,
        "description": finding.description,
        "filename": finding.filename,
        "line": finding.line_number,
        "fingerprint": finding.fingerprint,
        "evidence": finding.evidence,
        "created_at": finding.created_at,
    }


# Format Scan Details
def format_scan_detail(scan):
    return {
        "id": scan.id,
        "user_id": scan.user_id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "total_findings": scan.total_findings,
        "severity_summary": scan.severity_summary or {},
        "warnings": scan.warnings or [],
        "scanned_files": scan.scanned_files,
        "skipped_files": scan.skipped_files,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
        "findings": [
            format_finding(finding)
            for finding in scan.findings
        ],
    }


# Get Scans Visible to Current User
def get_visible_scans_query(
    db: Session,
    current_user: User
):
    query = db.query(Scan).options(
        joinedload(Scan.findings)
    )

    # Employees can only access their own scans.
    # Analysts and admins can access all scans.
    if current_user.role == "employee":
        query = query.filter(
            Scan.user_id == current_user.id
        )

    return query


# List Scan History
@router.get("/")
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_authenticated_user
    ),
):
    query = get_visible_scans_query(
        db,
        current_user
    )

    total_scans = query.count()

    scans = (
        query
        .order_by(Scan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total_scans": total_scans,
        "page": page,
        "page_size": page_size,
        "total_pages": (
            (total_scans + page_size - 1) // page_size
        ),
        "scans": [
            format_scan_detail(scan)
            for scan in scans
        ],
    }


# Get Specific Scan Details
@router.get("/{scan_id}")
def get_scan_details(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_authenticated_user
    ),
):
    query = get_visible_scans_query(
        db,
        current_user
    )

    scan = query.filter(
        Scan.id == scan_id
    ).first()

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    return format_scan_detail(scan)


# Clear all scan history (administrator only)
@router.delete("/clear")
def clear_scan_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete scan records and their findings while retaining audit logs."""
    scans = db.query(Scan).all()
    deleted_count = len(scans)

    try:
        for scan in scans:
            db.delete(scan)

        log_action(
            db=db,
            user_id=current_user.id,
            action="SCAN_HISTORY_CLEARED",
            resource_type="scan_history",
            details={"deleted_scan_count": deleted_count},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to clear scan history.",
        )

    return {
        "status": "success",
        "deleted_scans": deleted_count,
        "message": "Scan history cleared. Audit logs were retained.",
    }

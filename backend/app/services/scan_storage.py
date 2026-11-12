
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Scan, Finding


def save_scan(
    db: Session,
    user_id: int,
    scan_type: str,
    target: str,
    findings: list,
    severity_summary: dict,
    warnings: list | None = None,
    scanned_files: int | None = None,
    skipped_files: int | None = None,
):
    """
    Save a scan, its findings and extraction warnings.

    Evidence must already be redacted by the scanner.
    """

    scan = Scan(
        user_id=user_id,
        scan_type=scan_type,
        target=target,
        status="completed",
        total_findings=len(findings),
        severity_summary=severity_summary or {},
        warnings=warnings or [],
        scanned_files=scanned_files,
        skipped_files=skipped_files,
        completed_at=datetime.now(timezone.utc),
    )

    try:
        db.add(scan)
        db.flush()

        for item in findings:
            finding = Finding(
                scan_id=scan.id,
                rule=item.get("rule", "unknown"),
                severity=item.get("severity", "low"),
                description=item.get("description", ""),
                filename=item.get("filename", target),
                line_number=item.get("line"),
                fingerprint=item.get("fingerprint", ""),
                evidence=item.get("evidence", ""),
            )

            db.add(finding)

        db.commit()
        db.refresh(scan)

        return scan

    except Exception:
        db.rollback()
        raise


def format_scan(scan: Scan):
    return {
        "id": scan.id,
        "user_id": scan.user_id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "total_findings": scan.total_findings,
        "severity_summary": scan.severity_summary,
        "warnings": scan.warnings or [],
        "scanned_files": scan.scanned_files,
        "skipped_files": scan.skipped_files,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
    }

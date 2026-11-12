
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import AuditLog
from app.permissions import require_admin


router = APIRouter(
    prefix="/admin/audit-logs",
    tags=["Audit Logs"],
)


def format_audit_log(log):
    return {
        "id": log.id,
        "user_id": log.user_id,
        "username": log.user.username if log.user else None,
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "details": log.details,
        "ip_address": log.ip_address,
        "created_at": log.created_at,
    }


@router.get("/")
def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    action: str | None = Query(None),
    user_id: int | None = Query(None, ge=1),
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    query = db.query(AuditLog).options(
        joinedload(AuditLog.user)
    )

    if action:
        query = query.filter(AuditLog.action == action)

    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    total_logs = query.count()

    logs = (
        query
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total_logs": total_logs,
        "page": page,
        "page_size": page_size,
        "total_pages": (
            (total_logs + page_size - 1) // page_size
        ),
        "logs": [
            format_audit_log(log)
            for log in logs
        ],
    }

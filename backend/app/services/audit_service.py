
from sqlalchemy.orm import Session

from app.models import AuditLog


def log_action(
    db: Session,
    action: str,
    user_id: int = None,
    resource_type: str = None,
    resource_id: int = None,
    details: dict = None,
    ip_address: str = None,
):
    """
    Record an application activity in the audit log.
    """

    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
    )

    db.add(audit_entry)
    db.flush()

    return audit_entry


from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    JSON,
    CheckConstraint,
    Index,
)
from sqlalchemy.orm import relationship

from app.database import Base


# =========================
# USER MODEL
# =========================

class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'security_analyst', 'employee')",
            name="valid_user_role",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    username = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash = Column(
        String(255),
        nullable=False,
    )

    role = Column(
        String(30),
        nullable=False,
        default="employee",
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    scans = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
    )


# =========================
# SCAN MODEL
# =========================

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scan_type = Column(
        String(30),
        nullable=False,
    )

    target = Column(
        String(1024),
        nullable=True,
    )

    status = Column(
        String(30),
        default="completed",
        nullable=False,
    )

    total_findings = Column(
        Integer,
        default=0,
        nullable=False,
    )

    severity_summary = Column(
        JSON,
        default=dict,
        nullable=False,
    )

    # Stores extraction warnings and skipped-file information.
    warnings = Column(
        JSON,
        default=list,
        nullable=False,
    )

    scanned_files = Column(Integer, nullable=True)

    skipped_files = Column(Integer, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    completed_at = Column(
        DateTime,
        nullable=True,
    )

    user = relationship(
        "User",
        back_populates="scans",
    )

    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index(
            "idx_scan_user_created",
            "user_id",
            "created_at",
        ),
    )


# =========================
# FINDING MODEL
# =========================

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule = Column(
        String(100),
        nullable=False,
    )

    severity = Column(
        String(20),
        nullable=False,
    )

    description = Column(
        Text,
        nullable=True,
    )

    filename = Column(
        String(1024),
        nullable=True,
    )

    line_number = Column(
        Integer,
        nullable=True,
    )

    fingerprint = Column(
        String(64),
        nullable=True,
        index=True,
    )

    evidence = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    scan = relationship(
        "Scan",
        back_populates="findings",
    )


# =========================
# AUDIT LOG MODEL
# =========================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    action = Column(
        String(100),
        nullable=False,
    )

    resource_type = Column(
        String(100),
        nullable=True,
    )

    resource_id = Column(
        String(100),
        nullable=True,
    )

    details = Column(
        JSON,
        nullable=True,
    )

    ip_address = Column(
        String(45),
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    user = relationship(
        "User",
        back_populates="audit_logs",
    )

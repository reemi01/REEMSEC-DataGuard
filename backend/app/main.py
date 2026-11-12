
from pathlib import Path
import tempfile

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
)
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app import models
from app.models import User

from app.scanner.engine import scan_text, SECRET_PATTERNS
from app.services.file_scanner import (
    scan_file,
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
)
from app.services.directory_scanner import scan_directory
from app.services.scan_storage import save_scan
from app.services.audit_service import log_action

from app.permissions import (
    require_any_authenticated_user,
    require_analyst_or_admin,
)

from app.auth import router as auth_router
from app.user_management import router as user_management_router
from app.scan_history import router as scan_history_router
from app.audit_logs import router as audit_logs_router
from app.dashboard import router as dashboard_router


app = FastAPI(
    title="REEMSEC DataGuard",
    description=(
        "Universal Sensitive Data and Secret Exposure "
        "Detection Platform"
    ),
    version="0.8.0",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add defensive browser headers to API responses."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # Scan results may contain sensitive metadata; do not cache API responses.
        if request.url.path.startswith(("/auth", "/scan", "/scans", "/admin")):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response


app.add_middleware(SecurityHeadersMiddleware)


# =========================
# DATABASE INITIALIZATION
# =========================

def initialize_database():
    """
    Create missing tables and safely add missing columns.
    Existing records are preserved.
    """

    # Create tables that do not exist yet.
    Base.metadata.create_all(bind=engine)

    # Check existing scans table columns.
    inspector = inspect(engine)

    if "scans" not in inspector.get_table_names():
        raise RuntimeError(
            "Database initialization failed: scans table is missing."
        )

    columns = {
        column["name"]
        for column in inspector.get_columns("scans")
    }

    # Add warnings column only if it does not exist.
    if "warnings" not in columns:

        if engine.dialect.name == "sqlite":
            migration_sql = """
                ALTER TABLE scans
                ADD COLUMN warnings JSON NOT NULL DEFAULT '[]'
            """

        elif engine.dialect.name == "postgresql":
            migration_sql = """
                ALTER TABLE scans
                ADD COLUMN warnings JSON NOT NULL DEFAULT '[]'
            """

        else:
            raise RuntimeError(
                "Automatic warnings-column migration is not "
                f"configured for database: {engine.dialect.name}"
            )

        with engine.begin() as connection:
            connection.execute(text(migration_sql))

    # Add scan file counters for existing databases.
    for column_name in ("scanned_files", "skipped_files"):
        if column_name not in columns:
            with engine.begin() as connection:
                connection.execute(
                    text(f"ALTER TABLE scans ADD COLUMN {column_name} INTEGER")
                )


@app.on_event("startup")
def startup_event():
    initialize_database()


# =========================
# CORS CONFIGURATION
# =========================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# REGISTER API ROUTERS
# =========================

app.include_router(auth_router)
app.include_router(user_management_router)
app.include_router(scan_history_router)
app.include_router(audit_logs_router)
app.include_router(dashboard_router)


# =========================
# REQUEST MODELS
# =========================

class ScanRequest(BaseModel):
    # Prevent unexpectedly large text payloads from exhausting memory.
    content: str = Field(..., max_length=1_000_000)


class DirectoryScanRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)


# =========================
# SEVERITY SUMMARY
# =========================

def build_severity_summary(findings: list):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "low").lower()

        if severity in summary:
            summary[severity] += 1

    return summary


# =========================
# SCAN RESPONSE BUILDER
# =========================

def build_scan_response(
    filename: str,
    findings: list,
    warnings: list | None = None,
    scan_type: str | None = None,
):
    return {
        "status": "success",
        "filename": filename,
        "target": filename,
        "scan_type": scan_type,
        "findings_count": len(findings),
        "severity_summary": build_severity_summary(findings),
        "findings": findings,
        "warnings": warnings or [],
    }


# =========================
# AUDIT LOGGING
# =========================

def record_scan_audit(
    db: Session,
    current_user: User,
    saved_scan,
    scan_type: str,
    findings_count: int,
):
    log_action(
        db=db,
        user_id=current_user.id,
        action=f"{scan_type.upper()}_SCAN_CREATED",
        resource_type="scan",
        resource_id=str(saved_scan.id),
        details={
            "scan_type": scan_type,
            "findings_count": findings_count,
        },
    )

    db.commit()


# =========================
# ROOT ENDPOINT
# =========================

@app.get("/")
def root():
    return {
        "name": "REEMSEC DataGuard",
        "version": "0.8.0",
        "status": "running",
        "description": (
            "Universal Sensitive Data and Secret Exposure "
            "Detection Platform"
        ),
    }


# =========================
# HEALTH ENDPOINT
# =========================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "REEMSEC DataGuard",
    }


# =========================
# DETECTION RULES
# =========================

@app.get("/rules")
def get_detection_rules(
    current_user: User = Depends(require_analyst_or_admin),
):
    rules = []

    for rule_id, config in SECRET_PATTERNS.items():
        rules.append({
            "id": rule_id,
            "name": rule_id.replace("_", " ").title(),
            "severity": config["severity"],
            "description": config["description"],
            "status": "active",
        })

    return {
        "total_rules": len(rules),
        "rules": rules,
    }


# =========================
# TEXT SCAN
# =========================

@app.post("/scan")
def scan_content(
    request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated_user),
):
    findings = scan_text(request.content)

    response = build_scan_response(
        filename="text_input",
        findings=findings,
        scan_type="text",
    )

    saved_scan = save_scan(
        db=db,
        user_id=current_user.id,
        scan_type="text",
        target="text_input",
        findings=findings,
        severity_summary=response["severity_summary"],
        scanned_files=None,
        skipped_files=None,
    )

    record_scan_audit(
        db=db,
        current_user=current_user,
        saved_scan=saved_scan,
        scan_type="text",
        findings_count=len(findings),
    )

    response["scan_id"] = saved_scan.id

    return response


# =========================
# UNIVERSAL FILE SCAN
# =========================

@app.post("/scan-file")
async def scan_uploaded_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated_user),
):
    original_filename = file.filename or ""

    filename = (
        original_filename
        .replace("\\", "/")
        .split("/")[-1]
    )

    if not filename or filename in {".", ".."}:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="File type is not supported.",
        )

    try:
        content = await file.read(MAX_FILE_SIZE + 1)
    finally:
        await file.close()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File exceeds the maximum allowed size "
                f"of {MAX_FILE_SIZE // (1024 * 1024)} MB."
            ),
        )

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=extension,
            delete=False,
        ) as temporary_file:
            temporary_file.write(content)
            temporary_path = Path(temporary_file.name)

        scan_result = scan_file(str(temporary_path))

    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()

    if scan_result.get("status") != "success":
        raise HTTPException(
            status_code=400,
            detail=scan_result.get(
                "message",
                "File scan failed.",
            ),
        )

    findings = scan_result.get("findings", [])
    warnings = scan_result.get("warnings", [])

    response = build_scan_response(
        filename=filename,
        findings=findings,
        warnings=warnings,
        scan_type="file",
    )

    saved_scan = save_scan(
        db=db,
        user_id=current_user.id,
        scan_type="file",
        target=filename,
        findings=findings,
        severity_summary=response["severity_summary"],
        warnings=warnings,
        scanned_files=1,
        skipped_files=0,
    )

    record_scan_audit(
        db=db,
        current_user=current_user,
        saved_scan=saved_scan,
        scan_type="file",
        findings_count=len(findings),
    )

    response["scan_id"] = saved_scan.id
    response["file_size"] = len(content)
    response["file_type"] = extension.lstrip(".")
    response["scanned_files"] = 1
    response["skipped_files"] = 0

    return response


# =========================
# DIRECTORY SCAN
# =========================

@app.post("/scan-directory")
def scan_project_directory(
    request: DirectoryScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    scan_result = scan_directory(request.path)

    if scan_result.get("status") != "success":
        raise HTTPException(
            status_code=400,
            detail=scan_result.get(
                "message",
                "Directory scan failed.",
            ),
        )

    findings = scan_result.get("findings", [])
    warnings = scan_result.get("warnings", [])

    saved_scan = save_scan(
        db=db,
        user_id=current_user.id,
        scan_type="directory",
        target=request.path,
        findings=findings,
        severity_summary=scan_result.get(
            "severity_summary",
            build_severity_summary(findings),
        ),
        warnings=warnings,
        scanned_files=scan_result.get("scanned_files"),
        skipped_files=scan_result.get("skipped_files"),
    )

    record_scan_audit(
        db=db,
        current_user=current_user,
        saved_scan=saved_scan,
        scan_type="directory",
        findings_count=len(findings),
    )

    scan_result["scan_id"] = saved_scan.id

    return scan_result

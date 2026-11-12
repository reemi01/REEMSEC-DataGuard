from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import User
from app.permissions import (
    require_any_authenticated_user,
    require_analyst_or_admin,
)
from app.services.directory_scanner import PROJECT_ROOT


@pytest.fixture
def client(tmp_path):
    database_path = tmp_path / "api-test.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    db.add(User(
        id=1,
        username="api_test_admin",
        email="api-test@example.invalid",
        password_hash="not-used-in-dependency-overridden-tests",
        role="admin",
        is_active=True,
    ))
    db.commit()
    db.close()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    test_user = SimpleNamespace(id=1, role="admin")
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_any_authenticated_user] = lambda: test_user
    app.dependency_overrides[require_analyst_or_admin] = lambda: test_user

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_scan_file_accepts_valid_text_file(client):
    response = client.post(
        "/scan-file",
        files={"file": ("sample.txt", b'password = "FAKE_SECRET_123456"', "text/plain")},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["findings_count"] == 1
    assert result["findings"][0]["evidence"] == "[REDACTED]"
    assert result["scanned_files"] == 1
    assert result["skipped_files"] == 0


def test_scan_file_rejects_unsupported_extension(client):
    response = client.post(
        "/scan-file",
        files={"file": ("sample.exe", b"test", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "File type is not supported."


def test_scan_file_rejects_oversized_upload(client):
    from app.services.file_scanner import MAX_FILE_SIZE

    response = client.post(
        "/scan-file",
        files={"file": ("large.txt", b"A" * (MAX_FILE_SIZE + 1), "text/plain")},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "File exceeds the maximum allowed size of 10 MB."


def test_scan_file_rejects_invalid_utf8(client):
    response = client.post(
        "/scan-file",
        files={"file": ("invalid.txt", b"\xff\xfe\xfa", "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "File must contain valid UTF-8 text."


def test_scan_file_rejects_binary_content(client):
    response = client.post(
        "/scan-file",
        files={"file": ("binary.txt", b"hello\x00world", "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Binary files are not supported."


def test_scan_directory_accepts_project_root(client):
    response = client.post(
        "/scan-directory",
        json={"path": str(PROJECT_ROOT)},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert "scanned_files" in result
    assert "skipped_files" in result
    assert "findings_count" in result
    assert "severity_summary" in result


def test_scan_directory_rejects_outside_path(client, tmp_path):
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    response = client.post(
        "/scan-directory",
        json={"path": str(outside_directory)},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Access to this directory is not allowed."

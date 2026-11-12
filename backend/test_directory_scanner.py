
import pytest

from app.services.directory_scanner import scan_directory


@pytest.fixture
def allowed_test_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.services.directory_scanner.PROJECT_ROOT",
        tmp_path,
    )
    return tmp_path


def test_scans_supported_files_recursively(allowed_test_directory):
    subdirectory = allowed_test_directory / "src"
    subdirectory.mkdir()

    (allowed_test_directory / "config.txt").write_text(
        'password = "FAKE_SECRET_123456"',
        encoding="utf-8",
    )
    (subdirectory / "settings.py").write_text(
        'token = "ANOTHER_FAKE_SECRET_123"',
        encoding="utf-8",
    )

    result = scan_directory(str(allowed_test_directory))

    assert result["status"] == "success"
    assert result["scanned_files"] == 2
    assert result["findings_count"] == 2


def test_ignores_git_and_cache_directories(allowed_test_directory):
    git_dir = allowed_test_directory / ".git"
    cache_dir = allowed_test_directory / "__pycache__"

    git_dir.mkdir()
    cache_dir.mkdir()

    (git_dir / "secret.txt").write_text(
        'password = "FAKE_SECRET_123456"',
        encoding="utf-8",
    )
    (cache_dir / "secret.txt").write_text(
        'password = "FAKE_SECRET_123456"',
        encoding="utf-8",
    )

    result = scan_directory(str(allowed_test_directory))

    assert result["status"] == "success"
    assert result["scanned_files"] == 0
    assert result["findings_count"] == 0


def test_skips_unsupported_files(allowed_test_directory):
    (allowed_test_directory / "program.exe").write_text(
        "not supported",
        encoding="utf-8",
    )

    result = scan_directory(str(allowed_test_directory))

    assert result["status"] == "success"
    assert result["scanned_files"] == 0
    assert result["skipped_files"] == 1


def test_returns_error_for_missing_directory(allowed_test_directory):
    missing_dir = allowed_test_directory / "missing"

    result = scan_directory(str(missing_dir))

    assert result["status"] == "error"
    assert result["message"] == "Invalid directory path."


def test_rejects_directory_outside_project_root(allowed_test_directory):
    outside_directory = allowed_test_directory.parent / "outside"
    outside_directory.mkdir()

    result = scan_directory(str(outside_directory))

    assert result["status"] == "error"
    assert result["message"] == "Access to this directory is not allowed."

def test_returns_correct_severity_summary(allowed_test_directory):
    (allowed_test_directory / "secrets.txt").write_text(
        'password = "FAKE_SECRET_123456"\n'
        'aws_key = "AKIA1234567890ABCDEF"\n',
        encoding="utf-8",
    )

    result = scan_directory(str(allowed_test_directory))

    assert result["status"] == "success"
    assert result["findings_count"] == 2
    assert result["severity_summary"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
    }

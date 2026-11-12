
from app.services.file_scanner import scan_file, MAX_FILE_SIZE


def test_scans_text_file_and_detects_secret(tmp_path):
    fake_secret = "FAKE_SECRET_123456"
    test_file = tmp_path / "sample.txt"
    test_file.write_text(
        f'password = "{fake_secret}"',
        encoding="utf-8",
    )

    result = scan_file(str(test_file))

    assert result["status"] == "success"
    assert result["findings_count"] == 1
    assert result["findings"][0]["evidence"] == "[REDACTED]"
    assert fake_secret not in str(result)


def test_rejects_unsupported_file_type(tmp_path):
    test_file = tmp_path / "sample.exe"
    test_file.write_text("test", encoding="utf-8")

    result = scan_file(str(test_file))

    assert result["status"] == "error"
    assert result["message"] == "File type is not supported."


def test_rejects_file_larger_than_limit(tmp_path):
    test_file = tmp_path / "large.txt"
    test_file.write_text(
        "A" * (MAX_FILE_SIZE + 1),
        encoding="utf-8",
    )

    result = scan_file(str(test_file))

    assert result["status"] == "error"
    assert result["message"] == "File exceeds the 10 MB size limit."


def test_scans_empty_text_file(tmp_path):
    test_file = tmp_path / "empty.txt"
    test_file.write_text("", encoding="utf-8")

    result = scan_file(str(test_file))

    assert result["status"] == "success"
    assert result["findings_count"] == 0
    assert result["findings"] == []


def test_rejects_invalid_utf8_file(tmp_path):
    test_file = tmp_path / "invalid.txt"
    test_file.write_bytes(b"\xff\xfe\xfa")

    result = scan_file(str(test_file))

    assert result["status"] == "error"
    assert result["message"] == "File must contain valid UTF-8 text."


def test_rejects_binary_file_with_null_bytes(tmp_path):
    test_file = tmp_path / "binary.txt"
    test_file.write_bytes(b"hello\x00world")

    result = scan_file(str(test_file))

    assert result["status"] == "error"
    assert result["message"] == "Binary files are not supported."


from app.scanner.engine import scan_text


def test_detects_fake_github_token():
    fake_token = "github_pat_" + "A" * 30
    content = f'token = "{fake_token}"'

    findings = scan_text(content, "sample.py")

    assert any(
        finding["rule"] == "github_token"
        for finding in findings
    )


def test_secret_is_redacted():
    fake_secret = "FAKE_SECRET_123456"
    content = f'password = "{fake_secret}"'

    findings = scan_text(content, "sample.py")

    assert findings
    assert all(
        finding["evidence"] == "[REDACTED]"
        for finding in findings
    )
    assert fake_secret not in str(findings)


def test_normal_text_is_ignored():
    findings = scan_text(
        'message = "Hello, world!"',
        "sample.py",
    )

    assert findings == []
def test_detects_aws_access_key():
    fake_key = "AKIA" + "A" * 16
    content = f'aws_key = "{fake_key}"'

    findings = scan_text(content, "sample.py")

    assert any(
        finding["rule"] == "aws_access_key"
        for finding in findings
    )
def test_detects_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----"

    findings = scan_text(content, "sample.pem")

    assert any(
        finding["rule"] == "private_key"
        for finding in findings
    )
import hashlib
import re
from typing import Any


SECRET_PATTERNS: dict[str, dict[str, Any]] = {
    "aws_access_key": {
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "high",
        "description": "AWS access key identifier",
    },
    "github_token": {
        "pattern": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "severity": "high",
        "description": "GitHub personal access token",
    },
    "google_api_key": {
        "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "severity": "high",
        "description": "Google API key",
    },
    "stripe_secret_key": {
        "pattern": re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
        "severity": "critical",
        "description": "Stripe live secret key",
    },
    "slack_token": {
        "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "severity": "high",
        "description": "Slack access token",
    },
    "private_key": {
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        "severity": "critical",
        "description": "Private key header",
    },
    "jwt_token": {
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
        "severity": "high",
        "description": "JSON Web Token",
    },
    "database_connection_string": {
        "pattern": re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/"
            r"[^\s:/@]+:[^\s@]+@[^\s'\"<>]+",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "Database connection string containing credentials",
    },
    "generic_secret": {
        "pattern": re.compile(
            r"""(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|"""
            r"""token|access[_-]?key)\b\s*[:=]\s*"""
            r"""(?P<secret>['"]?)(?P<value>[^'"\s,;]{8,})"""
            r"""(?P=secret)"""
        ),
        "severity": "medium",
        "description": "Potential secret assigned to a sensitive variable",
    },
}


def _fingerprint(value: str) -> str:
    """Create a stable short identifier without exposing the secret."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def scan_text(content: str, filename: str = "unknown") -> list[dict]:
    """Find likely secrets and return redacted, line-level findings."""

    if not isinstance(content, str) or not content:
        return []

    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule_name, rule in SECRET_PATTERNS.items():
            for match in rule["pattern"].finditer(line):

                if rule_name == "generic_secret":
                    secret = match.group("value")
                else:
                    secret = match.group(0)

                fingerprint = _fingerprint(secret)

                dedupe_key = (
                    rule_name,
                    line_number,
                    fingerprint,
                )

                if dedupe_key in seen:
                    continue

                seen.add(dedupe_key)

                findings.append({
                    "rule": rule_name,
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "filename": filename,
                    "line": line_number,
                    "fingerprint": fingerprint,
                    "evidence": "[REDACTED]",
                })

    return findings
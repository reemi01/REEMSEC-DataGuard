import os
from pathlib import Path

from app.services.file_scanner import (
    ALLOWED_EXTENSIONS,
    scan_file,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".idea",
    ".vscode",
    "dist",
    "build",
    ".next",
    "coverage",
}

MAX_FILES_PER_SCAN = 5000


def _error(message: str) -> dict:
    return {
        "status": "error",
        "message": message,
    }


def scan_directory(directory_path: str) -> dict:
    """Scan supported files inside the allowed project directory."""

    try:
        root = Path(directory_path).resolve(strict=True)
        allowed_root = PROJECT_ROOT.resolve(strict=True)

        if not root.is_dir():
            return _error("Directory not found.")

        if not root.is_relative_to(allowed_root):
            return _error(
                "Access to this directory is not allowed."
            )

    except (OSError, RuntimeError, ValueError):
        return _error("Invalid directory path.")

    findings = []
    scanned_files = 0
    skipped_files = 0
    files_limit_reached = False

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):

        current_path = Path(current_root)

        # Ignore unnecessary and symbolic-link directories.
        directories[:] = [
            directory
            for directory in directories
            if directory not in DEFAULT_IGNORED_DIRS
            and not (current_path / directory).is_symlink()
        ]

        for filename in filenames:

            if scanned_files + skipped_files >= MAX_FILES_PER_SCAN:
                files_limit_reached = True
                break

            file_path = current_path / filename

            try:
                if file_path.is_symlink():
                    skipped_files += 1
                    continue

                if not file_path.is_file():
                    continue

                if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
                    skipped_files += 1
                    continue

                resolved_file = file_path.resolve(strict=True)

                if not resolved_file.is_relative_to(allowed_root):
                    skipped_files += 1
                    continue

                result = scan_file(str(resolved_file))

                if result["status"] != "success":
                    skipped_files += 1
                    continue

                scanned_files += 1

                relative_path = str(
                    resolved_file.relative_to(root)
                )

                for finding in result["findings"]:
                    finding["filename"] = relative_path
                    finding["file_path"] = relative_path
                    findings.append(finding)

            except (OSError, RuntimeError, ValueError):
                skipped_files += 1

        if files_limit_reached:
            break

    severity_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding["severity"].lower()

        if severity in severity_summary:
            severity_summary[severity] += 1

    return {
        "status": "success",
        "directory": root.name,
        "directory_path": str(root),
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "max_files_per_scan": MAX_FILES_PER_SCAN,
        "files_limit_reached": files_limit_reached,
        "findings_count": len(findings),
        "severity_summary": severity_summary,
        "findings": findings,
    }
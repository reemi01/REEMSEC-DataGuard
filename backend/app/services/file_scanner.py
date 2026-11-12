
from pathlib import Path
from io import BytesIO
import csv
import io
import xml.etree.ElementTree as ET
import zipfile

from pypdf import PdfReader
from docx import Document
from openpyxl import load_workbook
from PIL import Image
import pytesseract
import fitz

from app.scanner.engine import scan_text


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_ARCHIVE_SIZE = 25 * 1024 * 1024  # 25 MB extracted
MAX_ARCHIVE_FILES = 100
MAX_ARCHIVE_MEMBER_SIZE = 5 * 1024 * 1024  # 5 MB

TEXT_EXTENSIONS = {
    ".py", ".txt", ".env", ".js", ".ts", ".json",
    ".yaml", ".yml", ".ini", ".toml", ".php",
    ".html", ".css", ".sh", ".xml", ".csv", ".log",
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx",
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}
ARCHIVE_EXTENSIONS = {".zip"}

ALLOWED_EXTENSIONS = (
    TEXT_EXTENSIONS
    | DOCUMENT_EXTENSIONS
    | IMAGE_EXTENSIONS
    | ARCHIVE_EXTENSIONS
)


class FileScanError(Exception):
    """Raised when a file cannot be safely extracted or scanned."""


def _error(message: str) -> dict:
    return {
        "status": "error",
        "message": message,
    }


def _extract_text(filename: str, raw_content: bytes) -> str:
    """Extract readable text from supported file formats."""

    extension = Path(filename).suffix.lower()

    if extension in TEXT_EXTENSIONS:
        try:
            content = raw_content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise FileScanError(
                "File must contain valid UTF-8 text."
            )

        if "\x00" in content:
            raise FileScanError(
                "Binary files are not supported."
            )

        if extension == ".xml":
            try:
                root = ET.fromstring(content)
                return "\n".join(root.itertext())
            except ET.ParseError:
                raise FileScanError("Invalid XML document.")

        if extension == ".csv":
            try:
                rows = csv.reader(io.StringIO(content))
                return "\n".join(
                    " | ".join(row) for row in rows
                )
            except csv.Error:
                raise FileScanError("Invalid CSV document.")

        return content

    if extension in IMAGE_EXTENSIONS:
        try:
            image = Image.open(BytesIO(raw_content)).convert("RGB")
            return pytesseract.image_to_string(image)
        except pytesseract.pytesseract.TesseractNotFoundError:
            raise FileScanError("Image OCR requires Tesseract OCR to be installed.")
        except Exception:
            raise FileScanError("Unable to extract text from this image.")

    if extension == ".pdf":
        try:
            reader = PdfReader(BytesIO(raw_content))

            if reader.is_encrypted:
                raise FileScanError(
                    "Encrypted PDF files cannot be scanned."
                )

            pages = []

            for page in reader.pages:
                pages.append(page.extract_text() or "")

            extracted = "\n".join(pages).strip()
            if extracted:
                return extracted
            try:
                pdf = fitz.open(stream=raw_content, filetype="pdf")
                try:
                    ocr_pages = []
                    for page in pdf:
                        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                        image = Image.open(BytesIO(pix.tobytes("png"))).convert("RGB")
                        ocr_pages.append(pytesseract.image_to_string(image))
                    return "\n".join(ocr_pages)
                finally:
                    pdf.close()
            except pytesseract.pytesseract.TesseractNotFoundError:
                raise FileScanError("This scanned PDF needs Tesseract OCR installed.")
            except Exception:
                raise FileScanError("Unable to OCR this scanned PDF.")

        except FileScanError:
            raise
        except Exception:
            raise FileScanError(
                "Unable to extract text from this PDF."
            )

    if extension == ".docx":
        try:
            document = Document(BytesIO(raw_content))
            parts = []

            for paragraph in document.paragraphs:
                if paragraph.text.strip():
                    parts.append(paragraph.text)

            for table in document.tables:
                for row in table.rows:
                    parts.append(
                        " | ".join(cell.text for cell in row.cells)
                    )

            for section in document.sections:
                for paragraph in section.header.paragraphs:
                    if paragraph.text.strip():
                        parts.append(paragraph.text)

                for paragraph in section.footer.paragraphs:
                    if paragraph.text.strip():
                        parts.append(paragraph.text)

            return "\n".join(parts)

        except Exception:
            raise FileScanError(
                "Unable to read this Word document."
            )

    if extension == ".xlsx":
        try:
            workbook = load_workbook(
                BytesIO(raw_content),
                read_only=True,
                data_only=False,
            )

            parts = []

            try:
                for worksheet in workbook.worksheets:
                    parts.append(
                        f"Worksheet: {worksheet.title}"
                    )

                    for row in worksheet.iter_rows():
                        values = [
                            str(cell.value)
                            for cell in row
                            if cell.value is not None
                        ]

                        if values:
                            parts.append(" | ".join(values))
            finally:
                workbook.close()

            return "\n".join(parts)

        except Exception:
            raise FileScanError(
                "Unable to read this Excel document."
            )

    raise FileScanError("File type is not supported.")


def _scan_zip(raw_content: bytes) -> tuple[list, list]:
    """Scan supported files inside a ZIP without extracting to disk."""

    findings = []
    warnings = []
    total_uncompressed = 0
    scanned_files = 0

    try:
        archive = zipfile.ZipFile(BytesIO(raw_content))

        with archive:
            members = [
                item for item in archive.infolist()
                if not item.is_dir()
            ]

            if len(members) > MAX_ARCHIVE_FILES:
                raise FileScanError(
                    "ZIP archive contains too many files."
                )

            for item in members:
                member_path = Path(item.filename)
                extension = member_path.suffix.lower()

                if extension == ".zip":
                    warnings.append(
                        f"Nested ZIP archive skipped: {item.filename}"
                    )
                    continue

                if extension not in ALLOWED_EXTENSIONS:
                    warnings.append(
                        f"Unsupported file skipped: {item.filename}"
                    )
                    continue

                # Avoid scanning symbolic links in ZIP archives.
                unix_mode = (item.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    warnings.append(
                        f"Symbolic link skipped: {item.filename}"
                    )
                    continue

                if item.file_size > MAX_ARCHIVE_MEMBER_SIZE:
                    warnings.append(
                        f"File exceeds the archive member size limit: "
                        f"{item.filename}"
                    )
                    continue

                total_uncompressed += item.file_size

                if total_uncompressed > MAX_ARCHIVE_SIZE:
                    raise FileScanError(
                        "ZIP archive exceeds the total extracted size limit."
                    )

                if item.file_size > 0:
                    if item.compress_size == 0:
                        warnings.append(
                            f"Suspicious compressed file skipped: "
                            f"{item.filename}"
                        )
                        continue

                    compression_ratio = (
                        item.file_size / item.compress_size
                    )

                    if compression_ratio > 200:
                        warnings.append(
                            f"Suspicious compression ratio: "
                            f"{item.filename}"
                        )
                        continue

                try:
                    with archive.open(item) as file:
                        member_content = file.read(
                            MAX_ARCHIVE_MEMBER_SIZE + 1
                        )

                    if len(member_content) > MAX_ARCHIVE_MEMBER_SIZE:
                        warnings.append(
                            f"File exceeds the size limit: {item.filename}"
                        )
                        continue

                    extracted_text = _extract_text(
                        item.filename,
                        member_content,
                    )

                    member_findings = scan_text(
                        extracted_text,
                        f"{Path(item.filename).name} "
                        f"(inside ZIP: {item.filename})",
                    )

                    findings.extend(member_findings)
                    scanned_files += 1

                except FileScanError as exc:
                    warnings.append(
                        f"{item.filename}: {str(exc)}"
                    )

                except Exception:
                    warnings.append(
                        f"Unable to scan: {item.filename}"
                    )

    except FileScanError:
        raise
    except zipfile.BadZipFile:
        raise FileScanError("Invalid or corrupted ZIP archive.")
    except Exception:
        raise FileScanError("Unable to read ZIP archive.")

    if scanned_files == 0:
        warnings.append(
            "No supported files inside the ZIP archive were scanned."
        )

    return findings, warnings


def _build_severity_summary(findings: list) -> dict:
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "").lower()

        if severity in summary:
            summary[severity] += 1

    return summary


def scan_file(file_path: str) -> dict:
    """Scan supported documents, data files, code and ZIP archives."""

    path = Path(file_path)

    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return _error("File type is not supported.")

    try:
        if not path.is_file():
            return _error("File not found.")

        file_size = path.stat().st_size

        if file_size > MAX_FILE_SIZE:
            return _error(
                "File exceeds the 10 MB size limit."
            )

        with path.open("rb") as file:
            raw_content = file.read(MAX_FILE_SIZE + 1)

        if len(raw_content) > MAX_FILE_SIZE:
            return _error(
                "File exceeds the 10 MB size limit."
            )

        warnings = []

        if path.suffix.lower() == ".zip":
            findings, warnings = _scan_zip(raw_content)
        else:
            content = _extract_text(path.name, raw_content)

            if not content.strip():
                warnings.append(
                    "No readable text was extracted from this file."
                )

            findings = scan_text(content, path.name)

        return {
            "status": "success",
            "filename": path.name,
            "file_path": str(path.resolve()),
            "file_size": file_size,
            "findings_count": len(findings),
            "severity_summary": _build_severity_summary(findings),
            "findings": findings,
            "warnings": warnings,
        }

    except FileScanError as exc:
        return _error(str(exc))

    except OSError:
        return _error("Unable to read the file.")

    except Exception:
        return _error("An unexpected error occurred while scanning.")

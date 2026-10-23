"""
File Handler Utilities v01

Handles secure file upload, validation, and archive extraction.
"""

import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import UploadFile, HTTPException

from app.config import get_settings

settings = get_settings()


# --- Validation ---

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".rs", ".kt", ".swift", ".scala",
    ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg",
    ".sql", ".sh", ".bash", ".ps1", ".bat",
    ".dockerfile", ".dockerignore",
    ".zip", ".tar", ".gz", ".tgz", ".tar.gz",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".app",
    ".msi", ".deb", ".rpm", ".apk", ".ipa",
    ".jar", ".war", ".ear",
    ".class", ".pyc", ".pyo",
}


def validate_file(filename: str, file_size: int) -> None:
    """Validate uploaded file"""
    # Check extension
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # Check for double extensions (e.g., evil.php.jpg)
    if filename.count(".") > 1:
        # Check if any part is dangerous
        parts = filename.lower().split(".")
        for part in parts[:-1]:
            if f".{part}" in DANGEROUS_EXTENSIONS:
                raise HTTPException(400, "Suspicious file extension detected")

    # Check size
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max size: {settings.MAX_FILE_SIZE_MB}MB"
        )


# --- Save Upload ---

async def save_upload(file: UploadFile) -> str:
    """
    Save uploaded file to disk with secure filename.
    Returns the saved file path.
    """
    # Validate
    content = await file.read()
    validate_file(file.filename or "unknown", len(content))

    # Generate safe filename
    import uuid
    safe_name = f"{uuid.uuid4().hex}{Path(file.filename).suffix.lower()}"
    save_path = Path(settings.UPLOAD_DIR) / safe_name

    # Ensure upload directory exists
    save_path.parent.mkdir(parents=True, exist_ok=True)

    # Write file
    with open(save_path, "wb") as f:
        f.write(content)

    print(f"[FileHandler] Saved upload: {save_path} ({len(content)} bytes)")
    return str(save_path)


# --- Archive Extraction ---

def extract_archive(archive_path: str) -> str:
    """
    Extract zip/tar.gz archive to a temporary directory.
    Returns the extraction directory path.
    """
    archive_path = Path(archive_path)
    extract_dir = Path(settings.UPLOAD_DIR) / f"extracted_{archive_path.stem}"

    # Clean previous extraction
    if extract_dir.exists():
        shutil.rmtree(extract_dir)

    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        if archive_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                # Security: validate zip contents before extraction
                for member in zf.namelist():
                    member_path = Path(member)
                    # Prevent path traversal
                    if member_path.is_absolute() or ".." in member_path.parts:
                        raise HTTPException(400, f"Unsafe path in archive: {member}")
                zf.extractall(extract_dir)

        elif archive_path.suffix.lower() in [".tar", ".gz", ".tgz", ".tar.gz"]:
            with tarfile.open(archive_path, "r:*") as tf:
                # Security: validate tar contents
                for member in tf.getmembers():
                    if member.isabs() or ".." in member.name:
                        raise HTTPException(400, f"Unsafe path in archive: {member.name}")
                tf.extractall(extract_dir)

        else:
            raise HTTPException(400, f"Unsupported archive format: {archive_path.suffix}")

        print(f"[FileHandler] Extracted {archive_path} to {extract_dir}")
        return str(extract_dir)

    except (zipfile.BadZipFile, tarfile.TarError) as e:
        raise HTTPException(400, f"Corrupt or invalid archive: {e}")


# --- Cleanup ---

def cleanup_scan_files(scan_id: str) -> None:
    """Clean up temporary files for a scan"""
    upload_dir = Path(settings.UPLOAD_DIR)
    for item in upload_dir.glob(f"*{scan_id}*"):
        try:
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
        except Exception as e:
            print(f"[FileHandler] Cleanup warning: {e}")


def get_source_files(directory: str, extensions: Optional[list[str]] = None) -> list[Path]:
    """
    Get all source code files in a directory recursively.
    Used by scanners to know what to scan.
    """
    if extensions is None:
        extensions = [".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs"]

    source_files = []
    for ext in extensions:
        source_files.extend(Path(directory).rglob(f"*{ext}"))

    return source_files


# --- Quick Test ---

if __name__ == "__main__":
    # Test validation
    test_files = [
        ("app.py", 1000),
        ("script.js", 500),
        ("malware.exe", 1000),
        ("evil.php.jpg", 2000),
        ("large.zip", 100 * 1024 * 1024),  # 100MB
    ]

    for fname, fsize in test_files:
        try:
            validate_file(fname, fsize)
            print(f"✓ {fname} ({fsize} bytes) - OK")
        except HTTPException as e:
            print(f"✗ {fname} ({fsize} bytes) - REJECTED: {e.detail}")
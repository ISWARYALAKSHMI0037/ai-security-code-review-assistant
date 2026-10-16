"""Input validation helpers.

All code and files supplied by users are treated as UNTRUSTED text.
Nothing in this project ever executes that text.
"""
from __future__ import annotations

import os
import re
from typing import Optional, Tuple


class ValidationError(ValueError):
    """Raised when user input is not acceptable. The message is safe to show to users."""


SUPPORTED_LANGUAGES = ["Python", "JavaScript", "Java", "C", "C++"]

EXTENSION_TO_LANGUAGE = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".java": "Java",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
}
ALLOWED_EXTENSIONS = sorted(EXTENSION_TO_LANGUAGE)

MAX_UPLOAD_BYTES = 200 * 1024  # 200 KB per uploaded file
MAX_CODE_CHARS = 200_000       # limit for pasted code too
MAX_LINES = 5_000
MAX_FILENAME_LENGTH = 100

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._ -]")


def sanitize_filename(filename: object, default: str = "pasted_code.txt") -> str:
    """Return a harmless display filename (no folders, no odd characters)."""
    if not isinstance(filename, str):
        return default
    name = filename.replace("\\", "/").split("/")[-1]  # drop any folder part
    name = _UNSAFE_FILENAME_CHARS.sub("_", name).strip(" .")
    name = name[:MAX_FILENAME_LENGTH]
    return name or default


def get_extension(filename: str) -> str:
    """Lower-case file extension including the dot, e.g. '.py'."""
    return os.path.splitext(filename or "")[1].lower()


def detect_language_from_filename(filename: str) -> Optional[str]:
    """Guess the language from a file extension, or return None."""
    return EXTENSION_TO_LANGUAGE.get(get_extension(filename))


def validate_language(language: object) -> str:
    """Make sure the language is one we support."""
    if not isinstance(language, str) or language not in SUPPORTED_LANGUAGES:
        raise ValidationError(
            "Unsupported language. Please choose one of: " + ", ".join(SUPPORTED_LANGUAGES) + "."
        )
    return language


def validate_code(code: object) -> str:
    """Check pasted or uploaded code text and return it unchanged if acceptable."""
    if not isinstance(code, str):
        raise ValidationError("The code must be plain text.")
    if not code.strip():
        raise ValidationError("No code was provided. Paste some code or upload a file first.")
    if "\x00" in code:
        raise ValidationError("This looks like a binary file, not source code.")
    if len(code) > MAX_CODE_CHARS:
        raise ValidationError(
            f"The code is too long ({len(code):,} characters). The limit is {MAX_CODE_CHARS:,}."
        )
    if code.count("\n") + 1 > MAX_LINES:
        raise ValidationError(f"The code has too many lines. The limit is {MAX_LINES:,} lines.")
    return code


def validate_upload(filename: str, data: bytes) -> Tuple[str, str]:
    """Validate an uploaded file. Returns (code_text, language)."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValidationError("The uploaded file could not be read.")
    extension = get_extension(filename)
    if extension not in EXTENSION_TO_LANGUAGE:
        raise ValidationError(
            "Unsupported file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS) + "."
        )
    if len(data) == 0:
        raise ValidationError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValidationError(
            f"The file is too large. The limit is {MAX_UPLOAD_BYTES // 1024} KB per file."
        )
    try:
        code = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValidationError("The file is not valid UTF-8 text, so it cannot be analyzed.") from None
    validate_code(code)
    return code, EXTENSION_TO_LANGUAGE[extension]

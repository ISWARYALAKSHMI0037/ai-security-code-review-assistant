"""Combines Bandit, optional Semgrep and the built-in heuristic checks.

SAFETY NOTES
- Submitted code is NEVER executed. Bandit and Semgrep only read it.
- Tools are started with a fixed argument list (no shell) and a timeout.
- The only user-controlled data passed to a tool is a temporary FILE that we create ourselves
  with a fixed name inside a private temporary folder. It is deleted right after the scan.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from modules.vulnerability_checks import (
    KIND_HEURISTIC,
    KIND_TOOL,
    SEVERITIES,
    SEVERITY_RANK,
    Finding,
    make_finding,
    run_heuristic_checks,
)
from utils.validators import sanitize_filename, validate_code, validate_language

logger = logging.getLogger(__name__)

TOOL_TIMEOUT_SECONDS = 60

SEMGREP_EXTENSIONS = {"Python": ".py", "JavaScript": ".js", "Java": ".java", "C": ".c", "C++": ".cpp"}

# Bandit test id -> our category (used for explanations and for removing duplicates)
BANDIT_CATEGORIES = {
    "B102": "eval", "B307": "eval",
    "B105": "secret", "B106": "secret", "B107": "secret",
    "B201": "config", "B104": "config", "B501": "config", "B502": "config", "B503": "config",
    "B504": "config", "B505": "crypto",
    "B301": "deserialization", "B302": "deserialization", "B506": "deserialization",
    "B303": "crypto", "B304": "crypto", "B305": "crypto", "B324": "crypto",
    "B311": "random",
    "B602": "command", "B604": "command", "B605": "command", "B606": "command", "B607": "command",
    "B608": "sql", "B610": "sql", "B611": "sql",
    "B701": "xss", "B703": "xss", "B704": "xss",
}
BANDIT_SEVERITY = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
SEMGREP_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}


@dataclass
class AnalysisResult:
    """Everything produced by one scan."""

    filename: str
    language: str
    scanned_at: str
    line_count: int
    findings: List[Finding] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == "Critical")

    @property
    def warnings(self) -> int:
        """Number of heuristic (unconfirmed) warnings."""
        return sum(1 for f in self.findings if f.kind == KIND_HEURISTIC)

    def severity_counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


def bandit_available() -> bool:
    return importlib.util.find_spec("bandit") is not None


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _line_text(lines: List[str], line_number: Optional[int]) -> str:
    if isinstance(line_number, int) and 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def _run_bandit(code: str, lines: List[str]) -> Tuple[Optional[List[Finding]], Optional[str]]:
    """Run Bandit on a temporary copy of the code. Returns (findings or None, note)."""
    if not bandit_available():
        return None, ("Bandit is not installed, so only the built-in heuristic checks ran. "
                      "Install it with: pip install bandit")
    with tempfile.TemporaryDirectory(prefix="scan_") as folder:
        target = os.path.join(folder, "scan_target.py")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(code)  # written as text; never imported or executed
        command = [sys.executable, "-m", "bandit", "-f", "json", "-q", target]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS,
                check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            return None, "Bandit took too long and was stopped. Built-in checks still ran."
        except OSError:
            return None, "Bandit could not be started. Built-in checks still ran."
    try:
        data = json.loads(completed.stdout)
    except ValueError:
        return None, "Bandit did not return readable results. Built-in checks still ran."

    note = None
    if data.get("errors"):
        note = ("Bandit could not fully parse the code (it may contain a Python syntax error), "
                "so some checks may be missing.")
    findings: List[Finding] = []
    for item in data.get("results", []):
        test_id = str(item.get("test_id", ""))
        category = BANDIT_CATEGORIES.get(test_id, "other")
        line = item.get("line_number")
        line = line if isinstance(line, int) else None
        message = str(item.get("issue_text", "Potential security issue"))
        findings.append(
            make_finding(
                category=category,
                title=f"{message[:110]} [{test_id}]",
                severity=BANDIT_SEVERITY.get(str(item.get("issue_severity", "")).upper(), "Low"),
                line=line,
                snippet=_line_text(lines, line),
                confidence=str(item.get("issue_confidence", "Medium")).capitalize(),
                source="Bandit",
                kind=KIND_TOOL,
                rule_id=test_id,
                language="Python",
                tool_message=message,
            )
        )
    return findings, note


def _semgrep_category(check_id: str) -> str:
    lowered = check_id.lower()
    rules = [
        ("sql", "sql"), ("xss", "xss"), ("eval", "eval"), ("deserial", "deserialization"),
        ("pickle", "deserialization"), ("secret", "secret"), ("password", "secret"),
        ("hardcoded", "secret"), ("md5", "crypto"), ("sha1", "crypto"), ("crypto", "crypto"),
        ("command", "command"), ("subprocess", "command"), ("exec", "command"),
        ("path-traversal", "path"), ("tls", "config"), ("ssl", "config"), ("debug", "config"),
    ]
    for keyword, category in rules:
        if keyword in lowered:
            return category
    return "other"


def _run_semgrep(code: str, language: str, lines: List[str]) -> Tuple[Optional[List[Finding]], Optional[str]]:
    """Run Semgrep (if installed) on a temporary copy of the code."""
    executable = shutil.which("semgrep")
    if not executable:
        return None, "Semgrep is not installed, so it was skipped (it is optional)."
    extension = SEMGREP_EXTENSIONS[language]
    with tempfile.TemporaryDirectory(prefix="scan_") as folder:
        target = os.path.join(folder, "scan_target" + extension)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(code)
        command = [executable, "--config", "p/security-audit", "--json", "--quiet",
                   "--metrics", "off", "--timeout", "20", target]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS,
                check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            return None, "Semgrep took too long and was stopped."
        except OSError:
            return None, "Semgrep could not be started."
    try:
        data = json.loads(completed.stdout)
    except ValueError:
        return None, "Semgrep did not finish (it may need internet access to download its rules)."
    findings: List[Finding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {}) or {}
        line = (item.get("start", {}) or {}).get("line")
        line = line if isinstance(line, int) else None
        check_id = str(item.get("check_id", "semgrep"))
        message = str(extra.get("message", "Potential security issue"))
        confidence = str((extra.get("metadata", {}) or {}).get("confidence", "Medium")).capitalize()
        findings.append(
            make_finding(
                category=_semgrep_category(check_id),
                title=message[:110],
                severity=SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "Low"),
                line=line,
                snippet=_line_text(lines, line),
                confidence=confidence,
                source="Semgrep",
                kind=KIND_TOOL,
                rule_id=check_id.split(".")[-1],
                language=language,
                tool_message=message,
            )
        )
    return findings, None


def _merge(candidates: List[Finding]) -> List[Finding]:
    """Remove duplicates (same line and category). Earlier items win, so tools beat heuristics."""
    merged: List[Finding] = []
    seen = set()
    for finding in candidates:
        key = (finding.line, finding.category)
        if finding.line is not None and finding.category != "other" and key in seen:
            continue
        seen.add(key)
        merged.append(finding)
    merged.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.line or 0))
    return merged


def analyze_code(
    code: str,
    filename: str = "pasted_code.txt",
    language: str = "Python",
    use_bandit: bool = True,
    use_semgrep: bool = False,
) -> AnalysisResult:
    """Analyze code text and return an AnalysisResult. Raises ValidationError on bad input."""
    language = validate_language(language)
    validate_code(code)
    safe_name = sanitize_filename(filename)

    normalized = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    tools_used = ["Built-in heuristic checks"]
    notes: List[str] = []
    tool_findings: List[Finding] = []

    if use_bandit and language == "Python":
        found, note = _run_bandit(normalized, lines)
        if note:
            notes.append(note)
        if found is not None:
            tools_used.append("Bandit")
            tool_findings.extend(found)

    if use_semgrep:
        found, note = _run_semgrep(normalized, language, lines)
        if note:
            notes.append(note)
        if found is not None:
            tools_used.append("Semgrep")
            tool_findings.extend(found)

    heuristic_findings = run_heuristic_checks(normalized, language)
    findings = _merge(tool_findings + heuristic_findings)

    logger.info("Scan finished: %d findings using %s", len(findings), ", ".join(tools_used))
    return AnalysisResult(
        filename=safe_name,
        language=language,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        line_count=len(lines),
        findings=findings,
        tools_used=tools_used,
        notes=notes,
    )

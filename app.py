"""AI Security Code Review Assistant - Streamlit web app.

Start it with:  streamlit run app.py
"""
from __future__ import annotations

import html
import logging

import streamlit as st
from dotenv import load_dotenv

st.set_page_config(page_title="AI Security Code Review Assistant", page_icon="🛡️", layout="wide")
load_dotenv()  # reads a local .env file if present (never committed to Git)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app")

from modules.ai_review import AIConfigError, AIReviewResult, load_ai_config, review_code_with_ai  # noqa: E402
from modules.analyzer import analyze_code, bandit_available, semgrep_available  # noqa: E402
from modules.report_generator import build_report, report_to_json, report_to_markdown  # noqa: E402
from modules.vulnerability_checks import KIND_HEURISTIC, KIND_TOOL, SEVERITIES  # noqa: E402
from utils.validators import (ALLOWED_EXTENSIONS, MAX_CODE_CHARS, MAX_UPLOAD_BYTES,  # noqa: E402
                              SUPPORTED_LANGUAGES, ValidationError, sanitize_filename,
                              validate_upload)

PAGE_HOME = "🏠 Home"
PAGE_REVIEW = "🔍 Code Review"
PAGE_RESULTS = "📊 Results"
PAGE_ABOUT = "ℹ️ About & Help"
PAGES = [PAGE_HOME, PAGE_REVIEW, PAGE_RESULTS, PAGE_ABOUT]

SEVERITY_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "⚪"}
CODE_LANG = {"Python": "python", "JavaScript": "javascript", "Java": "java", "C": "c", "C++": "cpp"}
SAMPLE_CODE = '''import os
import sqlite3

DB_PASSWORD = "SuperSecret123"

def find_user(name):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()

def calculate(expression):
    return eval(expression)

def run(host):
    os.system("ping " + host)
'''

CSS = """
<style>
.block-container {padding-top: 2rem; max-width: 1200px;}
textarea {font-family: Consolas, "Courier New", monospace !important; font-size: 0.9rem !important;}
.hero {background: linear-gradient(135deg, #0b1f4d 0%, #070d1f 55%, #063447 100%);
       border: 1px solid #1d4ed8; border-radius: 16px; padding: 2rem 2.2rem; margin-bottom: 1.2rem;}
.hero h1 {margin: 0 0 .4rem 0; font-size: 2.1rem; color: #e6f1ff;}
.hero p {margin: 0; color: #9fb6d6; font-size: 1.05rem; max-width: 46rem;}
.feature {background: #0e1a36; border: 1px solid #1b3566; border-radius: 12px; padding: 1rem 1.2rem; margin-bottom: 1rem;}
.feature h4 {margin: 0 0 .3rem 0; color: #22d3ee;}
.feature p {margin: 0; color: #9fb6d6; font-size: .93rem;}
.metric-card {background: #0e1a36; border: 1px solid #1b3566; border-radius: 12px; padding: .9rem 1rem; text-align: center;}
.metric-value {font-size: 2rem; font-weight: 700; color: #e6f1ff; line-height: 1.1;}
.metric-label {color: #9fb6d6; font-size: .85rem;}
.badge {display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .8rem; font-weight: 600;}
.badge-Critical {background: #7f1d1d; color: #fecaca;}
.badge-High {background: #7c2d12; color: #fed7aa;}
.badge-Medium {background: #713f12; color: #fde68a;}
.badge-Low {background: #1e3a8a; color: #bfdbfe;}
.badge-Informational {background: #334155; color: #e2e8f0;}
.badge-tool {background: #064e3b; color: #a7f3d0;}
.badge-heuristic {background: #3b0764; color: #e9d5ff;}
</style>
"""

FEATURES = [
    ("🔎", "Static analysis", "Bandit plus safe built-in pattern checks for Python, JavaScript, Java, C and C++."),
    ("🧠", "Optional AI review", "Plain-English explanations from an LLM, clearly labeled. Works fine without a key."),
    ("🧩", "Secure code suggestions", "Vulnerable and safer code side by side, with what changed and why."),
    ("📄", "Downloadable reports", "Export your findings as JSON or Markdown."),
    ("🔒", "Privacy first", "Code is never run or saved. External AI is off unless you turn it on."),
    ("🎓", "Honest results", "Tool findings, heuristic warnings and AI text are always labeled separately."),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def init_state() -> None:
    st.session_state.setdefault("page", PAGE_HOME)
    st.session_state.setdefault("stats", {"files": 0, "findings": 0, "critical": 0, "warnings": 0})
    st.session_state.setdefault("result", None)
    st.session_state.setdefault("ai", None)


def go_to(page: str) -> None:
    st.session_state["page"] = page


def load_sample() -> None:
    """Button callback: runs before widgets are created, so it may set their values."""
    st.session_state["pasted_code"] = SAMPLE_CODE
    st.session_state["language"] = "Python"
    st.session_state["filename"] = "sample_app.py"


def get_ai_status():
    """Return (config, error_message). Keys come from environment variables or Streamlit secrets."""
    try:
        secrets = dict(st.secrets)
    except Exception:  # no secrets file is normal for local runs
        secrets = {}
    try:
        return load_ai_config(secrets), None
    except AIConfigError as exc:
        return None, str(exc)


def metric_card(label: str, value: object, icon: str, color: str) -> str:
    return (f'<div class="metric-card" style="border-top:3px solid {color}">'
            f'<div>{icon}</div><div class="metric-value">{html.escape(str(value))}</div>'
            f'<div class="metric-label">{html.escape(label)}</div></div>')


def render_dashboard_cards() -> None:
    stats = st.session_state["stats"]
    items = [("Files analyzed", stats["files"], "📁", "#22d3ee"),
             ("Vulnerabilities found", stats["findings"], "🛡️", "#3b82f6"),
             ("Critical issues", stats["critical"], "🚨", "#ef4444"),
             ("Warnings (heuristic)", stats["warnings"], "⚠️", "#f59e0b")]
    for column, item in zip(st.columns(4), items):
        column.markdown(metric_card(*item), unsafe_allow_html=True)  # values are numbers we generate
    st.caption("Totals for this browser session only. Nothing is stored on the server.")


def badge(severity: str) -> str:
    safe = html.escape(severity)
    return f'<span class="badge badge-{safe}">{safe}</span>'


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_home() -> None:
    st.markdown(
        '<div class="hero"><h1>🛡️ AI Security Code Review Assistant</h1>'
        "<p>Paste or upload source code and get a security review in plain English: what is risky, "
        "how it could be abused, and how to fix it. Runs locally with static analysis, with optional AI help.</p></div>",
        unsafe_allow_html=True)
    st.button("Start a code review", type="primary", on_click=go_to, args=(PAGE_REVIEW,))
    st.write("")
    render_dashboard_cards()
    st.subheader("What it does")
    for row_start in (0, 3):
        for column, (icon, title, text) in zip(st.columns(3), FEATURES[row_start:row_start + 3]):
            column.markdown(
                f'<div class="feature"><h4>{icon} {html.escape(title)}</h4><p>{html.escape(text)}</p></div>',
                unsafe_allow_html=True)


def page_review() -> None:
    st.header("🔍 Code Review")
    config, config_error = get_ai_status()

    source = st.radio("Where is the code?", ["Paste code", "Upload a file"], horizontal=True)
    language = st.selectbox("Programming language", SUPPORTED_LANGUAGES, key="language")
    filename = st.text_input("Filename", value="example.py", max_chars=100, key="filename")

    uploaded = None
    if source == "Paste code":
        st.button("Load sample vulnerable code", on_click=load_sample)
        st.text_area("Source code", height=340, key="pasted_code", max_chars=MAX_CODE_CHARS,
                     placeholder="Paste your code here...")
    else:
        uploaded = st.file_uploader("Upload a source file", type=[e.lstrip(".") for e in ALLOWED_EXTENSIONS])
        st.caption(f"Allowed: {', '.join(ALLOWED_EXTENSIONS)}. Maximum {MAX_UPLOAD_BYTES // 1024} KB. "
                   "The language is detected from the file extension.")

    st.subheader("Options")
    use_bandit = st.checkbox("Run Bandit (Python only)", value=True,
                             disabled=not bandit_available(),
                             help="Bandit is a Python security scanner. It reads the code but never runs it.")
    if not bandit_available():
        st.caption("Bandit is not installed here, so only the built-in checks will run.")
    use_semgrep = st.checkbox("Run Semgrep (optional)", value=False, disabled=not semgrep_available(),
                              help="Needs the semgrep program installed and internet access for its rules.")

    use_ai, consent = False, False
    if config:
        use_ai = st.checkbox(f"Add an external AI review ({config.provider})", value=False)
        if use_ai:
            st.warning(f"Your code will be sent to {config.provider}'s servers for analysis. "
                       "Do not send private or confidential code.")
            consent = st.checkbox("I understand and agree to send this code to the AI provider.")
    else:
        if config_error:
            st.warning(config_error)
        st.info("AI review is off because no API key is configured. Static analysis still works. "
                "See the README to add a key (optional).")

    if not st.button("🛡️ Analyze code", type="primary"):
        return

    try:
        if source == "Paste code":
            code, scan_language = st.session_state.get("pasted_code", ""), language
            scan_name = filename
        else:
            if uploaded is None:
                st.error("Please choose a file to upload first.")
                return
            code, scan_language = validate_upload(uploaded.name, uploaded.getvalue())
            scan_name = sanitize_filename(uploaded.name)

        with st.spinner("Analyzing your code..."):
            result = analyze_code(code, scan_name, scan_language,
                                  use_bandit=use_bandit and bandit_available(),
                                  use_semgrep=use_semgrep and semgrep_available())
            ai_result = None
            if use_ai and config:
                if consent:
                    ai_result = review_code_with_ai(code, scan_language, result.filename, config)
                else:
                    ai_result = AIReviewResult(ok=False, error="AI review was skipped because you did not "
                                                              "confirm that your code may be sent to the provider.")
    except ValidationError as exc:
        st.error(str(exc))
        return
    except Exception as exc:  # last-resort safety net; never show internals or secrets
        logger.error("Unexpected error during analysis: %s", type(exc).__name__)
        st.error("Something went wrong while analyzing the code. Please check the input and try again.")
        return

    stats = st.session_state["stats"]
    stats["files"] += 1
    stats["findings"] += result.total
    stats["critical"] += result.critical
    stats["warnings"] += result.warnings
    st.session_state["result"], st.session_state["ai"] = result, ai_result
    st.session_state["_goto"] = PAGE_RESULTS
    st.rerun()


def page_results() -> None:
    result = st.session_state.get("result")
    if result is None:
        st.info("No results yet. Run a code review first.")
        st.button("Start a code review", type="primary", on_click=go_to, args=(PAGE_REVIEW,))
        return
    ai_result = st.session_state.get("ai")

    st.header("📊 Security Report")
    st.caption(f"File: {result.filename} | Language: {result.language} | Scanned: {result.scanned_at} | "
               f"Tools: {', '.join(result.tools_used)}")
    render_dashboard_cards()
    for note in result.notes:
        st.info(note)

    counts = result.severity_counts()
    st.subheader("Summary of this scan")
    for column, severity in zip(st.columns(5), SEVERITIES):
        column.metric(f"{SEVERITY_ICONS[severity]} {severity}", counts[severity])
    st.caption("Tool findings come from Bandit or Semgrep. Heuristic warnings are pattern matches that can be "
               "false alarms. Neither list can catch every vulnerability.")

    left, right = st.columns(2)
    chosen = left.multiselect("Filter by severity", SEVERITIES, default=SEVERITIES)
    kinds = right.multiselect("Filter by analysis type", [KIND_TOOL, KIND_HEURISTIC],
                              default=[KIND_TOOL, KIND_HEURISTIC])
    shown = [f for f in result.findings if f.severity in chosen and f.kind in kinds]

    st.subheader(f"Findings ({len(shown)})")
    if not result.findings:
        st.success("No issues were detected by the checks that ran. This does not prove the code is secure.")
    elif not shown:
        st.info("No findings match the current filters.")
    for index, finding in enumerate(shown):
        line_label = f"line {finding.line}" if finding.line else "line n/a"
        label = f"{SEVERITY_ICONS[finding.severity]} {finding.severity}: {finding.title} ({line_label})"
        with st.expander(label, expanded=index < 3 and finding.severity in ("Critical", "High")):
            kind_class = "badge-tool" if finding.kind == KIND_TOOL else "badge-heuristic"
            st.markdown(
                f'{badge(finding.severity)} <span class="badge {kind_class}">{html.escape(finding.kind)}</span>',
                unsafe_allow_html=True)
            st.markdown(f"**Source:** {finding.source}  |  **Confidence:** {finding.confidence}  |  "
                        f"**Line:** {finding.line if finding.line else 'not available'}")
            st.markdown(f"**Why it is a risk:** {finding.why}")
            st.markdown(f"**How an attacker might abuse it (explained for defense):** {finding.attack}")
            st.markdown(f"**Recommended fix:** {finding.fix}")
            code_col, fixed_col = st.columns(2)
            code_col.markdown("**❌ Vulnerable code**")
            code_col.code(finding.snippet or "(not available)", language=CODE_LANG[result.language])
            fixed_col.markdown("**✅ Suggested secure code**")
            fixed_col.code(finding.secure_example, language=CODE_LANG[result.language])
            st.caption("What changed: the safer version keeps untrusted input separate from commands, "
                       "queries, or code, so it is treated only as data. Copy ideas into your own code "
                       "and test them; this tool never changes your code.")

    st.subheader("🤖 AI-generated review")
    st.caption("Written by a language model. It is separate from the static-analysis results above and "
               "may contain mistakes. Verify before relying on it.")
    if ai_result is None:
        st.info("AI review was not requested for this scan.")
    elif ai_result.ok:
        st.markdown(ai_result.text)  # raw HTML is not rendered; markdown images are removed
    else:
        st.warning(ai_result.error)

    st.subheader("⬇️ Download report")
    report = build_report(result, ai_result)
    stem = sanitize_filename(result.filename).rsplit(".", 1)[0] or "report"
    col_json, col_md = st.columns(2)
    col_json.download_button("Download JSON report", report_to_json(report),
                             file_name=f"security_report_{stem}.json", mime="application/json")
    col_md.download_button("Download Markdown report", report_to_markdown(report),
                           file_name=f"security_report_{stem}.md", mime="text/markdown")


def page_about() -> None:
    st.header("ℹ️ About & Help")
    st.markdown(
        """
**Project overview** - AI Security Code Review Assistant is a college project that reviews source code for
common security mistakes and explains them in simple language.

**How it works**
1. You paste code or upload a file (Python, JavaScript, Java, C or C++).
2. The app reads the code as text (it never runs it) with Bandit, optional Semgrep and built-in checks.
3. Results are shown with severity, line number, explanation, and a safer code example.
4. If you turned on AI review, a language model adds extra explanations in a separate section.
5. You can download the report as JSON or Markdown.

**Technologies** - Python, Streamlit, Bandit, Semgrep (optional), python-dotenv, requests, and an optional LLM API.

**How to use it**
- Open *Code Review*, choose a language, paste code (or load the sample), and press *Analyze code*.
- Use the filters on the *Results* page to focus on severe issues.
- Download a report to include in your assignment.

**Three kinds of results**
- *Static-analysis tool finding*: reported by Bandit or Semgrep.
- *Heuristic warning*: matched by a simple built-in pattern; may be a false alarm.
- *AI-generated*: written by a language model; not verified.

**Limitations of automated review**
- No tool finds every vulnerability, and every tool gives false alarms.
- Checks look at one file at a time and cannot see how code is used elsewhere.
- Multi-line statements and unusual coding styles can be missed.
- Results are advice, not a security guarantee. Have a person review important code.
- Only review code you are authorized to review.

**Privacy** - Code is analyzed in memory and not saved. It is sent to an AI provider only if you enable AI
review and confirm. Set `DISABLE_AI=true` to turn external AI off completely.
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
init_state()
st.markdown(CSS, unsafe_allow_html=True)  # static CSS written by us, not user content

if "_goto" in st.session_state:  # page change requested by a button; must run before the radio is created
    st.session_state["page"] = st.session_state.pop("_goto")

with st.sidebar:
    st.title("🛡️ Security Review")
    st.radio("Navigation", PAGES, key="page")
    st.divider()
    _config, _error = get_ai_status()
    if _config:
        st.success(f"AI review available ({_config.provider})")
    elif _error:
        st.warning(_error)
    else:
        st.info("AI review is off (no API key). Static analysis works.")
    st.caption("Code is never executed or stored.")

PAGE_FUNCTIONS = {PAGE_HOME: page_home, PAGE_REVIEW: page_review, PAGE_RESULTS: page_results, PAGE_ABOUT: page_about}
PAGE_FUNCTIONS[st.session_state["page"]]()

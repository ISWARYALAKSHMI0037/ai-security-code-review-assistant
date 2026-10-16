"""Tests for the AI Security Code Review Assistant.

Run from the project folder with:
    python -m unittest discover -s tests -v
No internet, API key, Streamlit or Bandit is required for these tests.
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # make project modules importable

from modules.ai_review import (AIConfigError, load_ai_config, review_code_with_ai,  # noqa: E402
                               sanitize_ai_text)
from modules.analyzer import analyze_code  # noqa: E402
from modules.report_generator import build_report, report_to_json, report_to_markdown  # noqa: E402
from utils.validators import (MAX_UPLOAD_BYTES, ValidationError, sanitize_filename,  # noqa: E402
                              validate_upload)

SAFE_CODE = '''import os


def add(a, b):
    return a + b


name = os.environ.get("USER_NAME", "friend")
print(add(1, 2), name)
'''


def categories(result):
    return {finding.category for finding in result.findings}


class TestSafeAndRiskyCode(unittest.TestCase):
    def test_safe_code_has_no_findings(self):
        result = analyze_code(SAFE_CODE, "safe.py", "Python", use_bandit=False)
        self.assertEqual(result.total, 0)

    def test_hardcoded_secret_is_found_and_masked(self):
        code = 'password = "SuperSecret123"\n'
        result = analyze_code(code, "config.py", "Python", use_bandit=False)
        self.assertIn("secret", categories(result))
        finding = result.findings[0]
        self.assertEqual(finding.line, 1)
        self.assertNotIn("SuperSecret123", finding.snippet)  # secrets are masked on screen and in reports

    def test_sql_string_concatenation(self):
        code = "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
        result = analyze_code(code, "db.py", "Python", use_bandit=False)
        self.assertIn("sql", categories(result))

    def test_parameterized_query_is_not_flagged(self):
        code = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
        result = analyze_code(code, "db.py", "Python", use_bandit=False)
        self.assertNotIn("sql", categories(result))

    def test_unsafe_eval(self):
        result = analyze_code("result = eval(user_input)\n", "calc.py", "Python", use_bandit=False)
        self.assertIn("eval", categories(result))
        self.assertEqual(result.findings[0].severity, "High")

    def test_literal_eval_and_model_eval_are_not_flagged(self):
        code = "import ast\nvalue = ast.literal_eval(text)\nmodel.eval()\n"
        result = analyze_code(code, "ok.py", "Python", use_bandit=False)
        self.assertNotIn("eval", categories(result))

    def test_other_languages(self):
        js = analyze_code("el.innerHTML = userText;\n", "a.js", "JavaScript", use_bandit=False)
        self.assertIn("xss", categories(js))
        c_code = analyze_code("char b[8];\ngets(b);\n", "a.c", "C", use_bandit=False)
        self.assertIn("memory", categories(c_code))
        self.assertEqual(c_code.critical, 1)
        java = analyze_code('Runtime.getRuntime().exec("ls " + dir);\n', "A.java", "Java", use_bandit=False)
        self.assertIn("command", categories(java))

    def test_bandit_enabled_does_not_crash_or_duplicate(self):
        # Works whether or not Bandit is installed (a note is added when it is missing).
        result = analyze_code("x = eval(data)\n", "t.py", "Python", use_bandit=True)
        eval_findings = [f for f in result.findings if f.category == "eval" and f.line == 1]
        self.assertEqual(len(eval_findings), 1)

    def test_heuristics_are_labelled(self):
        result = analyze_code("result = eval(x)\n", "t.py", "Python", use_bandit=False)
        self.assertEqual(result.findings[0].kind, "Heuristic warning")


class TestInputValidation(unittest.TestCase):
    def test_empty_input(self):
        for bad in ("", "   \n\t "):
            with self.assertRaises(ValidationError):
                analyze_code(bad, "x.py", "Python", use_bandit=False)

    def test_unsupported_language(self):
        with self.assertRaises(ValidationError):
            analyze_code("print(1)", "x.rb", "Ruby", use_bandit=False)

    def test_unsupported_file_types(self):
        for name in ("notes.txt", "program.exe", "archive.zip", "noextension"):
            with self.assertRaises(ValidationError):
                validate_upload(name, b"print('hi')")

    def test_supported_upload(self):
        code, language = validate_upload("tool.PY", b"print('hi')\n")
        self.assertEqual(language, "Python")
        self.assertIn("print", code)

    def test_upload_limits_and_binary(self):
        with self.assertRaises(ValidationError):
            validate_upload("big.py", b"a" * (MAX_UPLOAD_BYTES + 1))
        with self.assertRaises(ValidationError):
            validate_upload("empty.py", b"")
        with self.assertRaises(ValidationError):
            validate_upload("bin.py", b"\xff\xfe\x00\x01")

    def test_filename_sanitizing(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("<script>.py"), "_script_.py")
        self.assertEqual(sanitize_filename(""), "pasted_code.txt")


class TestAIConfiguration(unittest.TestCase):
    def test_missing_key_means_no_ai(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(load_ai_config())
            result = review_code_with_ai("print(1)", "Python", "a.py", None)
            self.assertFalse(result.ok)
            self.assertIn("no API key", result.error)

    def test_placeholder_key_is_ignored(self):
        with patch.dict(os.environ, {"AI_API_KEY": "your_api_key_here"}, clear=True):
            self.assertIsNone(load_ai_config())

    def test_invalid_provider(self):
        with patch.dict(os.environ, {"AI_API_KEY": "abc123", "AI_PROVIDER": "bogus"}, clear=True):
            with self.assertRaises(AIConfigError):
                load_ai_config()

    def test_ai_can_be_disabled(self):
        with patch.dict(os.environ, {"AI_API_KEY": "abc123", "DISABLE_AI": "true"}, clear=True):
            self.assertIsNone(load_ai_config())

    def test_key_from_secrets_and_not_in_repr(self):
        with patch.dict(os.environ, {}, clear=True):
            config = load_ai_config({"AI_API_KEY": "key-from-secrets", "AI_PROVIDER": "openai"})
        self.assertEqual(config.provider, "openai")
        self.assertNotIn("key-from-secrets", repr(config))

    def test_successful_call_is_parsed(self):
        with patch.dict(os.environ, {"AI_API_KEY": "abc123", "AI_PROVIDER": "anthropic"}, clear=True):
            config = load_ai_config()
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"content": [{"type": "text", "text": "Looks fine ![x](http://evil/p.png)"}]}
        with patch("modules.ai_review.requests.post", return_value=fake) as post:
            result = review_code_with_ai("print(1)", "Python", "a.py", config)
        self.assertTrue(result.ok)
        self.assertNotIn("http://evil", result.text)  # remote images are stripped
        self.assertEqual(post.call_args.kwargs["timeout"], 45)

    def test_provider_errors_never_leak_the_key(self):
        with patch.dict(os.environ, {"AI_API_KEY": "secret-key-999"}, clear=True):
            config = load_ai_config()
        for status in (401, 429, 500):
            fake = MagicMock(status_code=status)
            with patch("modules.ai_review.requests.post", return_value=fake):
                result = review_code_with_ai("print(1)", "Python", "a.py", config)
            self.assertFalse(result.ok)
            self.assertNotIn("secret-key-999", result.error)

    def test_gemini_is_default_and_parsed(self):
        with patch.dict(os.environ, {"AI_API_KEY": "gem-key-123"}, clear=True):
            config = load_ai_config()
        self.assertEqual(config.provider, "gemini")
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"candidates": [{"content": {"parts": [{"text": "Gemini says hi"}]}}]}
        with patch("modules.ai_review.requests.post", return_value=fake) as post:
            result = review_code_with_ai("print(1)", "Python", "a.py", config)
        self.assertTrue(result.ok)
        self.assertEqual(result.text, "Gemini says hi")
        self.assertNotIn("gem-key-123", post.call_args.args[0])  # key is not in the URL
        self.assertEqual(post.call_args.kwargs["headers"]["x-goog-api-key"], "gem-key-123")

    def test_bad_model_name_rejected(self):
        env = {"AI_API_KEY": "k12345", "AI_MODEL": "../evil?x=1"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(AIConfigError):
                load_ai_config()

    def test_sanitize_ai_text(self):
        self.assertNotIn("evil.test", sanitize_ai_text("hi ![a](https://evil.test/x.png) there"))


class TestReports(unittest.TestCase):
    def setUp(self):
        code = 'password = "SuperSecret123"\nresult = eval(data)\n'
        self.result = analyze_code(code, "demo.py", "Python", use_bandit=False)

    def test_json_report(self):
        report = build_report(self.result)
        parsed = json.loads(report_to_json(report))
        self.assertEqual(parsed["filename"], "demo.py")
        self.assertEqual(parsed["summary"]["total_findings"], 2)
        self.assertFalse(parsed["ai_review"]["included"])
        self.assertIn("line", parsed["findings"][0])
        self.assertNotIn("SuperSecret123", report_to_json(report))

    def test_markdown_report(self):
        markdown = report_to_markdown(build_report(self.result))
        for expected in ("demo.py", "High", "Recommended fix", "Disclaimer", "Scan date"):
            self.assertIn(expected, markdown)

    def test_report_with_no_findings(self):
        result = analyze_code(SAFE_CODE, "safe.py", "Python", use_bandit=False)
        markdown = report_to_markdown(build_report(result))
        self.assertIn("does not prove", markdown)


if __name__ == "__main__":
    unittest.main()

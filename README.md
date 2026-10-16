# AI Security Code Review Assistant

A Streamlit website that reviews Python, JavaScript, Java, C and C++ code for common security mistakes,
explains them in simple English, and suggests safer code. It works **without** any AI key (static analysis
only); an AI review is optional and always labeled separately.

> Status: written for a college project. It has **not** been deployed anywhere yet (see "Deployment").

## Folder structure

```
ai-security-code-review-assistant/
├── app.py                      # Streamlit website (start here)
├── requirements.txt
├── README.md
├── .env.example                # copy to .env for local settings
├── .gitignore
├── .streamlit/
│   └── config.toml             # dark navy/cyan theme and upload limit
├── modules/
│   ├── __init__.py
│   ├── analyzer.py             # runs Bandit / Semgrep / built-in checks, merges results
│   ├── vulnerability_checks.py # safe custom checks + explanations + secure examples
│   ├── ai_review.py            # optional LLM review (Gemini, Anthropic or OpenAI)
│   └── report_generator.py     # JSON and Markdown reports
├── utils/
│   ├── __init__.py
│   └── validators.py           # file type, size and input checks
└── tests/
    └── test_analyzer.py
```

Changes from the requested layout: `init.py` is written as the real Python name `__init__.py`, and
`.streamlit/config.toml` was added for the theme. The tests use Python's built-in `unittest`, so no extra
test library is needed.

## 1. Requirements

- Python 3.10 or newer (3.11 or 3.12 recommended) from https://www.python.org/downloads/
  (during install, tick **"Add python.exe to PATH"**).
- Check it: `python --version` (or `py --version`).

## 2. Setup on Windows

Open the project folder in a terminal.

**Command Prompt (cmd)**

```bat
cd path\to\ai-security-code-review-assistant
python -m venv venv
venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
streamlit run app.py
```

**PowerShell**

```powershell
cd path\to\ai-security-code-review-assistant
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
streamlit run app.py
```

If PowerShell refuses to activate the environment, run this once and try again:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

The app opens at http://localhost:8501. Stop it with `Ctrl+C`.

## 3. Optional AI review

The app works with the `.env` file left as is. To turn on AI review, edit `.env`:

```
AI_PROVIDER=gemini        # or anthropic / openai
AI_API_KEY=your-gemini-key-here   # from https://aistudio.google.com/apikey
AI_MODEL=                 # optional; default is gemini-2.5-flash
```

- Never share or commit `.env` (it is already in `.gitignore`).
- Even with a key, the app only sends code to the provider if you tick the AI option **and** confirm.
- Set `DISABLE_AI=true` to turn external AI off completely.
- You may set `AI_MODEL` to any model name your provider offers if the default is unavailable.

## 4. Run the tests

With the virtual environment active, from the project folder (same for cmd and PowerShell):

```
python -m unittest discover -s tests -v
```

The tests cover safe code, a hardcoded secret, SQL string building, unsafe `eval`, empty input,
unsupported files, missing/invalid AI configuration (the AI network call is mocked), and report generation.

## 5. How the analysis works

- **Static-analysis tool finding**: reported by Bandit (Python) or Semgrep (optional).
- **Heuristic warning**: matched by a built-in regex rule. May be a false alarm.
- **AI-generated**: written by an LLM, shown in its own section, never mixed with the others.

Safety design: code is never executed or imported; tools run with a fixed argument list (no shell), a
timeout, and a temporary file that is deleted afterwards; uploads are limited to 200 KB and to known
extensions; secrets in snippets are masked; AI output has remote images removed; nothing is stored.

Semgrep is optional and **not** in `requirements.txt` (it is heavy and does not run natively on Windows).
On Linux, macOS or WSL you can add it with `pip install semgrep`.

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python with "Add to PATH" ticked, or use `py` instead of `python`. |
| `'streamlit' is not recognized` | Activate the venv first, then `pip install -r requirements.txt`. |
| PowerShell blocks `Activate.ps1` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `ModuleNotFoundError: modules` | Run commands from the project folder (the one containing `app.py`). |
| "Bandit is not installed" note | `pip install bandit` inside the venv. Built-in checks still work. |
| Port 8501 already in use | `streamlit run app.py --server.port 8502` |
| AI says the key was rejected | Check `AI_API_KEY` and `AI_PROVIDER` in `.env`; restart the app after editing. |
| Upload rejected | Use `.py .js .mjs .java .c .h .cpp .cc .cxx .hpp`, UTF-8 text, under 200 KB. |

## 7. Upload to GitHub

1. Create a free account at https://github.com and install Git from https://git-scm.com/download/win.
2. On GitHub click **New repository**, name it `ai-security-code-review-assistant`, keep it empty (no README), create it.
3. In the project folder:

```
git init
git add .
git status
```

   Check that `.env` is **not** listed. Then:

```
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/ai-security-code-review-assistant.git
git push -u origin main
```

(Alternative: on the repository page choose **Add file > Upload files** and drag in everything except `.env` and `venv`.)

## 8. Deploy to Streamlit Community Cloud

1. Go to https://share.streamlit.io and sign in with GitHub.
2. Click **Create app** and pick your repository, branch `main`, and main file path `app.py`.
3. Open **Advanced settings**, choose Python 3.11 or 3.12, and (optional) paste your secrets:

```toml
AI_PROVIDER = "gemini"
AI_API_KEY = "your-gemini-key-here"
```

4. Click **Deploy** and wait for the dependencies to install.
5. Open the public URL, click *Load sample vulnerable code*, run a scan, and download a report to test it.

Secrets live only in Streamlit's settings, never in GitHub. You can add or change them later under the app's
**Settings > Secrets**. Without secrets, the deployed app still works with static analysis.

## Limitations

No automated tool finds every vulnerability. Results can include false alarms and miss real problems, and AI text
can be wrong. Use this as a learning aid and a first pass, and only on code you are authorized to review.

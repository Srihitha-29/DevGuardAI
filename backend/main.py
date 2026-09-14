from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os
import shutil
import zipfile
import uuid

# -------- Scanner imports --------
from scanner.sql_injection import detect_sql_injection
from scanner.hardcoded_secrets import detect_hardcoded_secrets
from scanner.weak_passwords import detect_weak_passwords
from scanner.insecure_http import detect_insecure_http
from scanner.command_injection import detect_command_injection
from scanner.eval_exec import detect_eval_exec
from scanner.security_score import calculate_security_score

# -------- AI import (hybrid: explains scanner findings AND
# independently audits each file for what regex patterns miss) --------
from ai.gemini_service import explain_vulnerability, audit_code, AIUnavailableError

# -------- Report generation --------
from report_generator import build_pdf_report

app = FastAPI(title="DevGuard AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Absolute paths so this works the same regardless of the working
# directory uvicorn was launched from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
EXTRACT_FOLDER = os.path.join(BASE_DIR, "extracted_projects")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)

REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# In-memory store so a PDF can be (re)built on demand after a scan,
# without needing a database for this version.
SCAN_RESULTS = {}

ALLOWED_EXTENSIONS = (".zip", ".java", ".py", ".js", ".cpp")
CODE_EXTENSIONS = (".java", ".py", ".js", ".cpp")

# High-level, deduped guidance for the "Recommendations" checklist —
# built from every issue's Gemini prevention_tips, one entry per
# unique vulnerability type actually found in this scan.


@app.get("/")
def home():
    return {
        "application": "DevGuard AI",
        "version": "3.0",
        "status": "Running",
    }


def scan_file(file_path: str):
    issues = []
    issues.extend(detect_sql_injection(file_path))
    issues.extend(detect_hardcoded_secrets(file_path))
    issues.extend(detect_weak_passwords(file_path))
    issues.extend(detect_insecure_http(file_path))
    issues.extend(detect_command_injection(file_path))
    issues.extend(detect_eval_exec(file_path))
    for issue in issues:
        issue["source"] = "scanner"
    return issues


def read_source(file_path: str) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def process_file(file_path: str):
    """
    Hybrid detection for one file:
    1. Regex scanner catches known patterns.
    2. Gemini independently audits the whole file for what the
       scanner's fixed patterns can't catch (auth/authorization
       logic, session handling, input validation, etc.) — skipping
       any vulnerability TYPE the scanner already flagged in this
       file, so the same issue isn't reported twice.

    Returns (issues, ai_audit_ok). ai_audit_ok is False when the
    Gemini call itself failed (quota exhausted, rate-limited) — that
    is NOT the same as the AI running and finding nothing, and callers
    must not present it as a clean result.
    """
    scanner_issues = scan_file(file_path)
    scanner_types_here = {i["type"] for i in scanner_issues}

    code_text = read_source(file_path)
    try:
        ai_findings = audit_code(file_path, code_text)
        ai_audit_ok = True
    except AIUnavailableError:
        ai_findings = []
        ai_audit_ok = False

    new_ai_findings = [f for f in ai_findings if f["type"] not in scanner_types_here]

    return scanner_issues + new_ai_findings, ai_audit_ok


def is_safe_member(member_name: str, extract_root: str) -> bool:
    """Reject zip entries that would escape the extraction folder
    (zip-slip / path traversal) before extraction ever touches disk."""
    target_path = os.path.abspath(os.path.join(extract_root, member_name))
    return target_path.startswith(os.path.abspath(extract_root) + os.sep)


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):

    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Unsupported file type.")

    # Unique id per upload so concurrent uploads (or repeat uploads of
    # the same filename) never collide or overwrite each other, and so
    # a crafted filename can't be used to escape UPLOAD_FOLDER.
    upload_id = uuid.uuid4().hex[:12]
    safe_ext = os.path.splitext(file.filename)[1]
    file_path = os.path.join(UPLOAD_FOLDER, f"{upload_id}{safe_ext}")

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    all_issues = []
    files_scanned = 0
    ai_audit_fully_ok = True

    if file.filename.lower().endswith(".zip"):
        project_folder = os.path.join(EXTRACT_FOLDER, upload_id)
        os.makedirs(project_folder, exist_ok=True)

        try:
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                safe_members = [
                    m for m in zip_ref.namelist()
                    if is_safe_member(m, project_folder)
                ]
                zip_ref.extractall(project_folder, members=safe_members)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Could not read ZIP file.")

        for root, _dirs, files in os.walk(project_folder):
            for filename in files:
                if filename.lower().endswith(CODE_EXTENSIONS):
                    current_file = os.path.join(root, filename)
                    files_scanned += 1
                    file_issues, file_ai_ok = process_file(current_file)
                    all_issues.extend(file_issues)
                    ai_audit_fully_ok = ai_audit_fully_ok and file_ai_ok

    else:
        files_scanned = 1
        file_issues, file_ai_ok = process_file(file_path)
        all_issues.extend(file_issues)
        ai_audit_fully_ok = ai_audit_fully_ok and file_ai_ok

    # -----------------------------
    # Gemini explains each scanner-found finding. AI-detected findings
    # already carry their own explanation/fix from audit_code(), so
    # they're skipped here to avoid a redundant second call.
    # -----------------------------
    seen_prevention_tips = []
    seen_tip_keys = set()

    def _add_tip(tip: str):
        key = " ".join(tip.lower().split())
        if key and key not in seen_tip_keys:
            seen_tip_keys.add(key)
            seen_prevention_tips.append(tip)

    for issue in all_issues:
        if issue.get("source") == "ai":
            # AI-detected findings already carry their own explanation/fix;
            # still contribute a recommendation so the checklist isn't
            # empty when only AI (no scanner) findings exist.
            _add_tip(f"Review and remediate: {issue['type']}.")
            continue
        ai_result = explain_vulnerability(issue["type"], issue["code"])
        issue["ai_explanation"] = ai_result.get("explanation", "")
        issue["secure_fix"] = ai_result.get("secure_fix", "")

        for tip in ai_result.get("prevention_tips", []):
            _add_tip(tip)

    # -----------------------------
    # Security score: 100 - 20*High - 10*Medium - 5*Low
    # -----------------------------
    score = calculate_security_score(all_issues)

    # The PDF report (report_generator.py) renders scanner findings and
    # AI findings as two separate tables/sections, so the stored record
    # for report generation needs them split — unlike the JSON response
    # below, which intentionally keeps them merged for the frontend to
    # filter client-side.
    scanner_only_issues = [i for i in all_issues if i.get("source") != "ai"]
    ai_only_issues = [i for i in all_issues if i.get("source") == "ai"]

    report_id = upload_id
    SCAN_RESULTS[report_id] = {
        "filename": file.filename,
        "files_scanned": files_scanned,
        "issues_found": scanner_only_issues,
        "ai_findings": ai_only_issues,
        "security_recommendations": seen_prevention_tips,
        "security_score": score,
        "ai_audit_available": ai_audit_fully_ok,
    }

    return {
        "filename": file.filename,
        "files_scanned": files_scanned,
        "issues_found": all_issues,
        "security_recommendations": seen_prevention_tips,
        "security_score": score,
        "report_id": report_id,
        "ai_audit_available": ai_audit_fully_ok,
    }


@app.get("/report/download/{report_id}")
def download_report(report_id: str):
    result = SCAN_RESULTS.get(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail="No scan found for this report_id.")

    pdf_path = os.path.join(REPORTS_FOLDER, f"{report_id}.pdf")
    build_pdf_report(pdf_path, result)

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="devguard-report.pdf",
    )
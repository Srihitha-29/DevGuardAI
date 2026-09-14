"""
Hybrid AI role in DevGuardAI:
1. explain_vulnerability() — explains + suggests a fix for each finding
   the regex scanner already caught.
2. audit_code() — independently reviews the FULL file for issues the
   scanner's fixed patterns can't catch: broken auth/authorization
   logic, missing input validation, insecure session/token handling,
   logic-level flaws in things like a UserController or LoginLogger,
   etc. This is what lets a scan surface real problems even when the
   regex scanner finds nothing on its own.
"""

import os
import json
from google import genai
from google.genai import types
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Guard against a missing key, AND cap how long a single Gemini call
# can take. Without a timeout, one slow/stuck API call blocks the
# whole /upload request indefinitely — this is the most likely cause
# of a scan that hangs forever on the loading screen for a big project.
client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options=types.HttpOptions(timeout=60_000),  # 60s, in ms
        )
    except Exception:
        client = None

# gemini-2.5-flash was retired for new API keys; Google's own API error
# points new callers at gemini-3.6-flash as the replacement.
MODEL_NAME = "gemini-3.6-flash"


class AIUnavailableError(Exception):
    """Raised when the Gemini call itself couldn't be completed (quota
    exhausted, rate-limited, etc) — as opposed to the model running fine
    and simply reporting no findings. Callers must not treat this the
    same as a clean result."""
    pass


def _is_quota_or_rate_limit_error(exc: Exception) -> bool:
    text = str(exc)
    return "429" in text or "RESOURCE_EXHAUSTED" in text or "quota" in text.lower()

FALLBACK = {
    "SQL Injection": {
        "explanation": "This query is built by concatenating input directly into SQL, letting an attacker inject their own SQL and read, modify, or delete data they shouldn't have access to.",
        "secure_fix": "Use a parameterized query / prepared statement instead of string concatenation.",
        "prevention_tips": [
            "Use parameterized queries or an ORM for all database access.",
            "Never build SQL by concatenating user input.",
        ],
    },
    "Hardcoded Secret": {
        "explanation": "An API key, token, or credential is embedded directly in source code. Anyone with access to the repo (or a leaked build) can steal and misuse it.",
        "secure_fix": "Load the value from an environment variable instead of hardcoding it.",
        "prevention_tips": [
            "Store secrets in environment variables or a secrets manager, never in source.",
            "Rotate any credential that was ever committed to version control.",
        ],
    },
    "Weak Password": {
        "explanation": "A weak or common password is hardcoded in source. Hardcoded credentials can't be rotated and are trivially guessable.",
        "secure_fix": "Remove the hardcoded value and require a strong password set at runtime/configuration.",
        "prevention_tips": [
            "Never hardcode credentials in source code.",
            "Enforce a minimum password strength policy wherever passwords are set.",
        ],
    },
    "Insecure HTTP URL": {
        "explanation": "This request uses plaintext HTTP, exposing data in transit to interception or tampering.",
        "secure_fix": "Change the URL scheme from http:// to https://.",
        "prevention_tips": [
            "Use HTTPS for all network requests.",
            "Enable HSTS on servers you control.",
        ],
    },
    "Command Injection": {
        "explanation": "This calls out to the shell/interpreter with data that could be attacker-controlled, allowing arbitrary command execution.",
        "secure_fix": "Avoid shell=True / Runtime.exec() with dynamic input; use an argument list and validate/allow-list values.",
        "prevention_tips": [
            "Never pass unsanitized input to a shell or interpreter.",
            "Prefer library calls over shelling out where possible.",
        ],
    },
    "Dangerous eval()/exec()": {
        "explanation": "eval()/exec() run arbitrary code built from a string at runtime. If any part of that string comes from user input, it allows arbitrary code execution.",
        "secure_fix": "Replace eval()/exec() with a safe alternative (e.g. ast.literal_eval for data, or an explicit dispatch table for logic).",
        "prevention_tips": [
            "Avoid eval()/exec() entirely where a safer alternative exists.",
            "If unavoidable, strictly validate and sandbox the input.",
        ],
    },
}


def _fallback(issue_type: str) -> dict:
    return FALLBACK.get(issue_type, {
        "explanation": "This pattern is commonly associated with a security risk.",
        "secure_fix": "Review secure coding guidance for this vulnerability class.",
        "prevention_tips": ["Review and remediate this finding manually."],
    })


def _parse(text: str) -> dict:
    cleaned = text.strip().replace("```json", "").replace("```", "").strip()
    data = json.loads(cleaned)
    return {
        "explanation": data.get("explanation", ""),
        "secure_fix": data.get("secure_fix", ""),
        "prevention_tips": data.get("prevention_tips", []) or [],
    }


def explain_vulnerability(issue_type: str, code_snippet: str) -> dict:
    """
    Returns {"explanation": str, "secure_fix": str, "prevention_tips": [str]}.
    Falls back to canned guidance if no API key is set or the call fails,
    so a scan never breaks on an AI error.
    """
    if client is None:
        return _fallback(issue_type)

    prompt = f"""You are an expert cybersecurity code auditor.

Vulnerability type: {issue_type}

Vulnerable code:
{code_snippet}

Return ONLY valid JSON in this exact format:
{{
  "explanation": "2-3 sentences on why this is risky",
  "secure_fix": "a short corrected code snippet or concrete fix",
  "prevention_tips": ["tip 1", "tip 2"]
}}
"""

    try:
        response = client.models.generate_content(model=MODEL_NAME, contents=prompt)
        return _parse(response.text)
    except Exception:
        return _fallback(issue_type)


# Cap how much source we send per file — keeps prompts fast/cheap and
# avoids hitting model input limits on very large files.
MAX_AUDIT_CHARS = 12_000


def audit_code(file_path: str, code_text: str) -> list:
    """
    Independently reviews a full file for security issues beyond what
    the regex scanner's fixed patterns can catch — logic-level flaws
    like missing authorization checks, broken auth logic, insecure
    session/token handling, improper error handling that leaks
    sensitive info, etc.

    Returns a list of finding dicts:
    [{"type", "severity", "line", "code", "ai_explanation", "secure_fix"}]

    Returns an empty list (never fabricates findings) if there's no
    client, the file is empty, or the call/parse fails — this is
    supplemental detection, so a safe default is "found nothing new"
    rather than guessing.
    """
    if client is None:
        print(f"[audit_code] SKIPPED for {file_path} — client is None (no valid GEMINI_API_KEY set)")
        return []
    if not code_text.strip():
        print(f"[audit_code] SKIPPED for {file_path} — file read as empty")
        return []

    truncated = code_text[:MAX_AUDIT_CHARS]
    print(f"[audit_code] Calling Gemini for {file_path} ({len(truncated)} chars)...")

    # Framed explicitly as a defensive code-review task performed on the
    # developer's OWN code, not as "finding vulnerabilities" in the
    # abstract — some models treat vulnerability-hunting language as
    # adversarial and refuse outright even for entirely benign code.
    prompt = f"""You are a senior software engineer performing a routine secure-coding
code review on your own team's file, {os.path.basename(file_path)}, before it
ships. This is a standard defensive code-quality review, the same kind every
team runs on its own code before a release.

A separate automated tool already checks for SQL injection, hardcoded
secrets, weak passwords, insecure HTTP, command injection, and eval/exec
misuse — skip those, they're already covered.

Please review the code below for other secure-coding best-practice gaps a
simple pattern checker would miss, such as: missing input validation, missing
authorization checks on sensitive operations, insecure session or token
handling, error handling that could leak internal details, logging or
printing sensitive data in plaintext (passwords, tokens, API keys, or other
PII written to logs/console/stdout), or similar defensive-coding gaps. If the
file is fine as-is, just say so with an empty list.

Code to review:
{truncated}

Respond with ONLY valid JSON in this exact format (empty list if nothing to flag):
{{
  "findings": [
    {{
      "type": "short, descriptive name for the gap",
      "severity": "High" | "Medium" | "Low",
      "line": <line number or null>,
      "code": "the relevant line or short snippet",
      "explanation": "2-3 sentences on why this matters",
      "secure_fix": "a short corrected approach or code snippet"
    }}
  ]
}}
"""

    # Backup measure alongside the reframed prompt above: lower the
    # dangerous-content safety threshold for this specific call, since
    # a defensive code-review tool legitimately needs to discuss
    # security weaknesses without every mention being treated as risky.
    safety_settings = [
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
    ]

    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                safety_settings=safety_settings,
                # Note: Gemini 3.x models (including gemini-3.6-flash) ignore
                # temperature/top_p/top_k entirely — Google manages sampling
                # internally for these models now, so that knob is removed
                # rather than left in as dead configuration.
            ),
        )

        # Distinguish "model refused / returned no candidates" from
        # "returned text that failed to parse as JSON" — these need
        # very different fixes, so don't lump them into one error.
        if not response.candidates:
            print(f"[audit_code] BLOCKED for {file_path}: no candidates returned "
                  f"(prompt_feedback={getattr(response, 'prompt_feedback', None)})")
            return []

        finish_reason = getattr(response.candidates[0], "finish_reason", None)
        if finish_reason is not None and str(finish_reason) not in ("STOP", "1", "FinishReason.STOP"):
            print(f"[audit_code] Non-normal finish_reason for {file_path}: {finish_reason}")

        print(f"[audit_code] Raw Gemini response for {file_path}:\n{response.text!r}\n")
        cleaned = response.text.strip().replace("```json", "").replace("```", "").strip()
        data = json.loads(cleaned)
        findings = data.get("findings", []) or []
        print(f"[audit_code] Parsed {len(findings)} finding(s) for {file_path}")

        results = []
        for f in findings:
            if not f.get("type"):
                continue
            results.append({
                "type": f.get("type"),
                "severity": f.get("severity", "Medium"),
                "file": os.path.basename(file_path),
                "line": f.get("line"),
                "code": f.get("code", ""),
                "ai_explanation": f.get("explanation", ""),
                "secure_fix": f.get("secure_fix", ""),
                "source": "ai",
            })
        return results
    except json.JSONDecodeError:
        print(f"[audit_code] REFUSED or NON-JSON response for {file_path} — "
              f"the model likely declined the request rather than returning "
              f"findings. See the raw response text printed above.")
        return []
    except Exception as e:
        if _is_quota_or_rate_limit_error(e):
            print(f"[audit_code] QUOTA/RATE-LIMIT hit for {file_path}: {e}")
            raise AIUnavailableError(str(e)) from e
        print(f"[audit_code] FAILED for {file_path}: {type(e).__name__}: {e}")
        return []
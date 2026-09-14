import re

COMMON_WEAK_WORDS = [
    "password",
    "admin",
    "root",
    "qwerty",
    "welcome",
    "test",
    "guest",
    "user"
]


def detect_weak_passwords(file_path):
    issues = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        for line_no, line in enumerate(lines, start=1):

            match = re.search(
                r'password\s*=\s*[\'"]([^\'"]+)[\'"]',
                line,
                re.IGNORECASE
            )

            if not match:
                continue

            password = match.group(1).lower()

            weak = False
            severity = "Medium"

            # Common weak keywords
            if any(word in password for word in COMMON_WEAK_WORDS):
                weak = True
                severity = "High"

            # Very short passwords
            elif len(password) < 8:
                weak = True
                severity = "Medium"

            # Numeric-only passwords
            elif password.isdigit():
                weak = True
                severity = "High"

            # Simple letter+number pattern
            elif re.fullmatch(r"[a-z]+\d+", password):
                weak = True
                severity = "Medium"

            if weak:
                issues.append({
                    "type": "Weak Password",
                    "severity": severity,
                    "line": line_no,
                    "code": line.strip()
                })

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return issues
import os
COMMAND_PATTERNS = [
    "Runtime.getRuntime().exec(",
    "ProcessBuilder(",
    "system("
]


def detect_command_injection(file_path):

    issues = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    for line_number, line in enumerate(lines, start=1):

        for pattern in COMMAND_PATTERNS:

            if pattern in line:
                issues.append({
                    "type": "Command Injection",
                    "file": os.path.basename(file_path),
                    "severity": "High",
                    "line": line_number,
                    "code": line.strip()
                })

    return issues
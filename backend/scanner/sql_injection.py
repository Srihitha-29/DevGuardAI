import os
import re

def detect_sql_injection(file_path):

    issues = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    pattern = r"(SELECT|INSERT|UPDATE|DELETE).*\+"

    for line_number, line in enumerate(lines, start=1):

        if re.search(pattern, line, re.IGNORECASE):
            issues.append({
                "type": "SQL Injection",
                    "file": os.path.basename(file_path),
                "severity": "High",
                "line": line_number,
                "code": line.strip()
            })

    return issues
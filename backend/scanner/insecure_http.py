import os
def detect_insecure_http(file_path):

    issues = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    for line_number, line in enumerate(lines, start=1):

        if "http://" in line:
            issues.append({
                "type": "Insecure HTTP URL",
                    "file": os.path.basename(file_path),
                "severity": "Low",
                "line": line_number,
                "code": line.strip()
            })

    return issues
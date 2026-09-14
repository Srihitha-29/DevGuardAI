import re

# Case-insensitive patterns for common secrets
SECRET_PATTERNS = [
    r"(api[_-]?key)\s*=\s*[\"'][^\"']+[\"']",
    r"(secret[_-]?key)\s*=\s*[\"'][^\"']+[\"']",
    r"(jwt[_-]?secret)\s*=\s*[\"'][^\"']+[\"']",
    r"(access[_-]?token)\s*=\s*[\"'][^\"']+[\"']",
    r"(client[_-]?secret)\s*=\s*[\"'][^\"']+[\"']",
    r"(private[_-]?key)\s*=\s*[\"'][^\"']+[\"']",
    r"(bearer[_-]?token)\s*=\s*[\"'][^\"']+[\"']",
]


def detect_hardcoded_secrets(file_path):
    issues = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        for line_no, line in enumerate(lines, start=1):
            for pattern in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "Hardcoded Secret",
                        "severity": "High",
                        "line": line_no,
                        "code": line.strip()
                    })
                    break

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return issues
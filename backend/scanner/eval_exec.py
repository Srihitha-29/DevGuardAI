def detect_eval_exec(file_path):

    issues = []

    # Only scan Python and JavaScript files
    if not file_path.endswith((".py", ".js")):
        return issues

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        if stripped.startswith("eval(") or stripped.startswith("exec("):
            issues.append({
                "type": "Dangerous eval()/exec()",
                "severity": "High",
                "file": file_path.split("/")[-1].split("\\")[-1],
                "line": line_number,
                "code": stripped
            })

    return issues
def calculate_security_score(issues):
    """
    Score = 100 - (20 x High) - (10 x Medium) - (5 x Low)
    """
    score = 100

    for issue in issues:
        severity = issue.get("severity")

        if severity == "High":
            score -= 20
        elif severity == "Medium":
            score -= 10
        elif severity == "Low":
            score -= 5

    return max(score, 0)
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from xml.sax.saxutils import escape as xml_escape


# ==========================================================
# DEVGUARD AI V4 PDF REPORT GENERATOR
# ==========================================================

styles = getSampleStyleSheet()

title_style = styles["Heading1"]
title_style.alignment = TA_CENTER
title_style.textColor = HexColor("#2563EB")

heading_style = styles["Heading2"]
heading_style.textColor = HexColor("#7C3AED")

normal_style = styles["BodyText"]


# ----------------------------------------------------------
# Escaping helpers
# ----------------------------------------------------------
# ReportLab's Paragraph treats its input as a small XML dialect
# (it understands tags like <b>, <font>, <br/>). Any raw source
# code snippet we insert can legally contain '<', '>' or '&'
# (generics, comparisons, template literals, XML/HTML source
# files, etc). Left unescaped, those characters are parsed as
# markup and raise an XML parse error, crashing report
# generation. Every dynamic value MUST go through esc()/esc_code()
# before being placed inside a Paragraph string.

def esc(value):
    """Escape a plain (single-line) dynamic value for safe use inside a Paragraph."""
    if value is None:
        return ""
    return xml_escape(str(value))


def esc_code(value):
    """Escape a multi-line code snippet and convert newlines to <br/> for Paragraph."""
    if value is None:
        return ""
    escaped = xml_escape(str(value))
    return escaped.replace("\n", "<br/>")


# ----------------------------------------------------------
# Severity Badge Color
# ----------------------------------------------------------

def severity_color(level):
    level = (level or "").lower()

    if level == "critical":
        return colors.darkred

    if level == "high":
        return colors.red

    if level == "medium":
        return colors.orange

    return colors.green


# ----------------------------------------------------------
# Issue Table
# ----------------------------------------------------------

def issue_table(title, findings):

    elements = []

    elements.append(Paragraph(esc(title), heading_style))
    elements.append(Spacer(1, 0.15 * inch))

    if not findings:

        elements.append(
            Paragraph(
                "✅ No issues found in this category.",
                normal_style
            )
        )

        elements.append(Spacer(1, 0.2 * inch))
        return elements

    data = [["Type", "Severity", "File", "Line"]]

    for issue in findings:

        data.append([
            esc(issue.get("type", "")),
            esc(issue.get("severity", "")),
            esc(issue.get("file", "")),
            esc(issue.get("line", "-"))
        ])

    table = Table(data, colWidths=[2.3*inch,1*inch,1.8*inch,0.6*inch])

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),HexColor("#2563EB")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,0),8),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("BACKGROUND",(0,1),(-1,-1),HexColor("#F8FAFC")),

        ("VALIGN",(0,0),(-1,-1),"TOP"),

    ]))

    elements.append(table)
    elements.append(Spacer(1, 0.25 * inch))

    return elements


# ----------------------------------------------------------
# Detailed Findings Section
# ----------------------------------------------------------

def detailed_findings(title, findings):

    elements = []

    elements.append(Paragraph(esc(title), heading_style))
    elements.append(Spacer(1, 0.15 * inch))

    if not findings:

        elements.append(
            Paragraph(
                "No findings available.",
                normal_style
            )
        )

        elements.append(Spacer(1, 0.2 * inch))
        return elements

    for index, issue in enumerate(findings, start=1):

        severity = issue.get("severity", "Low")

        elements.append(
            Paragraph(
                f"<b>{index}. {esc(issue.get('type'))}</b>",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<font color='{severity_color(severity)}'><b>Severity:</b> {esc(severity)}</font>",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<b>File:</b> {esc(issue.get('file'))}",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<b>Line:</b> {esc(issue.get('line'))}",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<b>Vulnerable Code:</b><br/>{esc_code(issue.get('code'))}",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<b>Why it's risky:</b><br/>{esc_code(issue.get('ai_explanation'))}",
                normal_style
            )
        )

        elements.append(
            Paragraph(
                f"<b>Secure Fix:</b><br/>{esc_code(issue.get('secure_fix'))}",
                normal_style
            )
        )

        elements.append(Spacer(1,0.18*inch))

    return elements


# ==========================================================
# BUILD PDF
# ==========================================================

def build_pdf_report(output_path, report):

    doc = SimpleDocTemplate(output_path, pagesize=A4)

    elements = []

    # ------------------------------------------------------
    # Header
    # ------------------------------------------------------

    elements.append(Paragraph("DevGuard AI Security Audit Report", title_style))
    elements.append(Spacer(1,0.3*inch))

    if report.get("ai_audit_available") is False:
        elements.append(
            Paragraph(
                "<font color='#DC2626'><b>⚠ AI audit did not complete for one or more files "
                "(Gemini API quota/rate limit reached). The findings below reflect the static "
                "scanner only and are NOT a full security clearance.</b></font>",
                normal_style
            )
        )
        elements.append(Spacer(1,0.2*inch))

    # ------------------------------------------------------
    # Project Summary
    # ------------------------------------------------------

    elements.append(Paragraph("Project Summary", heading_style))

    summary_data = [

        ["Project", esc(report["filename"])],

        ["Files Scanned", esc(report["files_scanned"])],

        ["Security Score", f"{esc(report['security_score'])} / 100"],

        ["Scanner Findings", esc(len(report["issues_found"]))],

        ["AI Findings", esc(len(report["ai_findings"]))],

    ]

    summary_table = Table(summary_data, colWidths=[2.2*inch,3.2*inch])

    summary_table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(0,-1),HexColor("#E0F2FE")),

        ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("BACKGROUND",(1,0),(1,-1),colors.whitesmoke),

    ]))

    elements.append(summary_table)
    elements.append(Spacer(1,0.3*inch))

    # ------------------------------------------------------
    # Security Score
    # ------------------------------------------------------

    elements.append(Paragraph("Security Score", heading_style))

    score = report["security_score"]

    if score >= 90:
        rating = "Excellent Security"
        color = "#16A34A"

    elif score >= 70:
        rating = "Good Security"
        color = "#E8A33D"

    elif score >= 50:
        rating = "Moderate Risk"
        color = "#EA580C"

    else:
        rating = "High Risk — Needs Immediate Attention"
        color = "#DC2626"

    elements.append(
        Paragraph(
            f"<font color='{color}' size=16><b>{esc(score)}/100 — {rating}</b></font>",
            normal_style
        )
    )

    elements.append(Spacer(1,0.25*inch))

    # ------------------------------------------------------
    # Scanner Findings Summary
    # ------------------------------------------------------

    elements.extend(issue_table(
        "Scanner Findings (Regex Detection)",
        report["issues_found"]
    ))

    # ------------------------------------------------------
    # AI Findings Summary
    # ------------------------------------------------------

    elements.extend(issue_table(
        "AI Findings (Contextual Security Detection)",
        report["ai_findings"]
    ))

    # ------------------------------------------------------
    # Scanner Findings Details
    # ------------------------------------------------------

    elements.extend(detailed_findings(
        "Scanner Findings - Detailed Analysis",
        report["issues_found"]
    ))

    # ------------------------------------------------------
    # AI Findings Details
    # ------------------------------------------------------

    elements.extend(detailed_findings(
        "AI Findings - Detailed Analysis",
        report["ai_findings"]
    ))

    # ------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------

    elements.append(Paragraph("Security Recommendations", heading_style))
    elements.append(Spacer(1,0.12*inch))

    recommendations = report.get("security_recommendations", [])

    if recommendations:

        for tip in recommendations:

            elements.append(
                Paragraph(
                    f"• {esc(tip)}",
                    normal_style
                )
            )

    else:

        elements.append(
            Paragraph(
                "No additional recommendations generated.",
                normal_style
            )
        )

    elements.append(Spacer(1,0.3*inch))

    # ------------------------------------------------------
    # Footer
    # ------------------------------------------------------

    elements.append(
        Paragraph(
            "<b>Generated by DevGuard AI V4 — Hybrid Static & AI Security Auditor</b>",
            normal_style
        )
    )

    elements.append(
        Paragraph(
            "Files are analyzed in an isolated workspace and never executed. "
            "The scanner performs static analysis only.",
            normal_style
        )
    )

    doc.build(elements)
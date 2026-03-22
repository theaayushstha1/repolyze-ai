"""Generate professional PDF security audit reports.

Uses reportlab to create a multi-page PDF with:
- Cover page with repo name, date, overall grade
- Executive summary with severity counts and key metrics
- Findings grouped by category with severity badges
- Agent safety section with grade and details
- Remediation recommendations
"""

import io
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colors ─────────────────────────────────────────────────────────────────

BRAND = HexColor("#1a1a2e")
ACCENT = HexColor("#0f3460")
HIGHLIGHT = HexColor("#e94560")
WHITE = HexColor("#ffffff")
LIGHT_GRAY = HexColor("#f0f0f0")
GRAY_BORDER = HexColor("#cccccc")

SEVERITY_COLORS = {
    "CRITICAL": HexColor("#dc2626"),
    "HIGH": HexColor("#ea580c"),
    "MEDIUM": HexColor("#ca8a04"),
    "LOW": HexColor("#2563eb"),
    "INFO": HexColor("#6b7280"),
}

GRADE_COLORS = {
    "A": HexColor("#16a34a"),
    "B": HexColor("#65a30d"),
    "C": HexColor("#ca8a04"),
    "D": HexColor("#ea580c"),
    "F": HexColor("#dc2626"),
}


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    custom = {
        "CoverTitle": ParagraphStyle(
            "CoverTitle", fontSize=32, leading=40, alignment=TA_CENTER,
            textColor=BRAND, fontName="Helvetica-Bold", spaceAfter=8,
        ),
        "CoverSub": ParagraphStyle(
            "CoverSub", fontSize=13, leading=18, alignment=TA_CENTER,
            textColor=ACCENT, fontName="Helvetica",
        ),
        "SectionTitle": ParagraphStyle(
            "SectionTitle", fontSize=18, leading=24, textColor=BRAND,
            fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=8,
        ),
        "SubHead": ParagraphStyle(
            "SubHead", fontSize=13, leading=17, textColor=ACCENT,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4,
        ),
        "Body": ParagraphStyle(
            "Body", fontSize=10, leading=14, textColor=HexColor("#333"),
            fontName="Helvetica", spaceAfter=4,
        ),
        "Bullet": ParagraphStyle(
            "Bullet", fontSize=10, leading=14, textColor=HexColor("#333"),
            fontName="Helvetica", leftIndent=18, spaceAfter=2,
        ),
        "Code": ParagraphStyle(
            "Code", fontSize=8, leading=11, textColor=HexColor("#1a1a1a"),
            fontName="Courier", leftIndent=12, backColor=LIGHT_GRAY, spaceAfter=4,
        ),
        "Meta": ParagraphStyle(
            "Meta", fontSize=10, leading=14, alignment=TA_CENTER,
            textColor=HexColor("#666"), fontName="Helvetica",
        ),
    }
    return {**{s.name: s for s in base.byName.values()}, **custom}


def _hr():
    return HRFlowable(width="100%", thickness=1, color=GRAY_BORDER, spaceAfter=8)


def _make_table(headers: list[str], rows: list[list[str]], col_widths=None):
    data = [headers, *rows]
    if col_widths is None:
        available = 6.5 * inch
        col_widths = [available / len(headers)] * len(headers)
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def generate_report_pdf(scan: dict[str, Any], findings: list[dict[str, Any]]) -> bytes:
    """Generate a PDF audit report and return it as bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )
    s = _build_styles()
    story: list[Any] = []

    # ── Cover Page ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("Security Audit Report", s["CoverTitle"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(scan.get("repo_name", "Unknown"), s["CoverSub"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%B %d, %Y')} by RepolyzeAI",
        s["Meta"],
    ))
    story.append(Spacer(1, 30))

    # Overall grade badge
    grade = scan.get("agent_safety_grade", "N/A")
    grade_color = GRADE_COLORS.get(grade, HexColor("#666"))
    story.append(Paragraph(
        f'<font color="{grade_color}" size="48"><b>{grade}</b></font>',
        ParagraphStyle("GradeBig", alignment=TA_CENTER, fontSize=48, leading=56),
    ))
    story.append(Paragraph("Overall Security Grade", s["Meta"]))
    story.append(Spacer(1, 20))
    story.append(_hr())
    story.append(Paragraph(
        f'{scan.get("total_findings", 0)} findings across '
        f'{len(scan.get("languages_detected", []))} languages',
        s["Meta"],
    ))
    story.append(PageBreak())

    # ── Executive Summary ──────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", s["SectionTitle"]))
    story.append(_hr())

    summary_data = [
        ["Total Findings", str(scan.get("total_findings", 0))],
        ["Critical", str(scan.get("critical_count", 0))],
        ["High", str(scan.get("high_count", 0))],
        ["Medium", str(scan.get("medium_count", 0))],
        ["Low", str(scan.get("low_count", 0))],
        ["Info", str(scan.get("info_count", 0))],
        ["Languages", ", ".join(scan.get("languages_detected", []) or ["N/A"])],
        ["AI Agents", ", ".join(scan.get("agents_detected", []) or ["None detected"])],
        ["MCP Servers", "Detected" if scan.get("mcp_detected") else "None"],
        ["Safety Grade", grade],
        ["Scan Duration", f'{scan.get("scan_duration_ms", 0)}ms'],
    ]
    story.append(_make_table(
        ["Metric", "Value"], summary_data,
        col_widths=[2.5 * inch, 4 * inch],
    ))
    story.append(Spacer(1, 12))

    # Risk summary paragraph
    total = scan.get("total_findings", 0)
    crits = scan.get("critical_count", 0)
    highs = scan.get("high_count", 0)
    if crits > 0:
        risk_msg = (f"<b>CRITICAL RISK:</b> {crits} critical vulnerabilities require "
                    "immediate attention before deployment.")
    elif highs > 0:
        risk_msg = (f"<b>HIGH RISK:</b> {highs} high-severity issues found. "
                    "Address these before production deployment.")
    elif total > 0:
        risk_msg = (f"<b>MODERATE RISK:</b> {total} findings detected. "
                    "Review and address medium/low severity items.")
    else:
        risk_msg = "<b>LOW RISK:</b> No significant vulnerabilities detected."
    story.append(Paragraph(risk_msg, s["Body"]))
    story.append(PageBreak())

    # ── Findings by Category ───────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", s["SectionTitle"]))
    story.append(_hr())

    grouped: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        grouped[f.get("category", "other")].append(f)

    for category, cat_findings in sorted(grouped.items()):
        story.append(Paragraph(
            f'{category.replace("_", " ").title()} ({len(cat_findings)} findings)',
            s["SubHead"],
        ))

        rows = []
        for f in sorted(cat_findings, key=lambda x: _sev_order(x.get("severity", "INFO"))):
            rows.append([
                f.get("severity", "?"),
                f.get("title", "")[:60],
                f.get("file_path", "N/A"),
                str(f.get("line_start", "")),
            ])

        story.append(_make_table(
            ["Severity", "Finding", "File", "Line"], rows,
            col_widths=[0.8 * inch, 2.8 * inch, 2.2 * inch, 0.7 * inch],
        ))
        story.append(Spacer(1, 8))

        # Remediation for first finding in category
        if cat_findings and cat_findings[0].get("remediation"):
            story.append(Paragraph(
                f'\u2192 <b>Remediation:</b> {cat_findings[0]["remediation"]}',
                s["Bullet"],
            ))
        story.append(Spacer(1, 6))

    story.append(PageBreak())

    # ── Agent Safety Assessment ────────────────────────────────────────────
    agent_findings = [f for f in findings if f.get("agent_name") == "agent_safety"]
    if agent_findings:
        story.append(Paragraph("AI Agent Safety Assessment", s["SectionTitle"]))
        story.append(_hr())
        story.append(Paragraph(
            f'Safety Grade: <font color="{grade_color}" size="16"><b>{grade}</b></font>',
            s["Body"],
        ))
        story.append(Spacer(1, 8))

        for f in agent_findings:
            story.append(Paragraph(
                f'\u2022 <b>[{f.get("severity", "?")}]</b> {f.get("title", "")}',
                s["Bullet"],
            ))
            if f.get("file_path"):
                story.append(Paragraph(
                    f'&nbsp;&nbsp;&nbsp;&nbsp;File: {f["file_path"]}:{f.get("line_start", "")}',
                    s["Code"],
                ))
            if f.get("remediation"):
                story.append(Paragraph(
                    f'&nbsp;&nbsp;&nbsp;&nbsp;\u2192 {f["remediation"]}',
                    s["Bullet"],
                ))
        story.append(PageBreak())

    # ── MCP Audit ──────────────────────────────────────────────────────────
    mcp_findings = [f for f in findings if f.get("agent_name") == "mcp_auditor"]
    if mcp_findings:
        story.append(Paragraph("MCP Server Audit", s["SectionTitle"]))
        story.append(_hr())
        for f in mcp_findings:
            story.append(Paragraph(
                f'\u2022 <b>[{f.get("severity", "?")}]</b> {f.get("title", "")}',
                s["Bullet"],
            ))
            if f.get("remediation"):
                story.append(Paragraph(
                    f'&nbsp;&nbsp;&nbsp;&nbsp;\u2192 {f["remediation"]}',
                    s["Bullet"],
                ))
        story.append(PageBreak())

    # ── Footer ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("Generated by RepolyzeAI", s["Meta"]))
    story.append(Paragraph("https://repolyze.ai", s["Meta"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "This report is for informational purposes. Always verify findings manually.",
        s["Meta"],
    ))

    doc.build(story)
    return buf.getvalue()


def _sev_order(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)

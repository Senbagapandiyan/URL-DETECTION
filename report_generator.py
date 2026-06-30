import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(scan_result):
    """Create a PDF report for a single scan result."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="Phishing Detection Report")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=24,
        textColor=colors.HexColor("#1d4ed8"),
        spaceAfter=12,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["BodyText"],
        fontSize=11,
        leading=14,
        textColor=colors.grey,
        spaceAfter=12,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontSize=11,
        leading=14,
        spaceAfter=8,
    )

    story = []
    story.append(Paragraph("Phishing Website Detection Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    story.append(Spacer(1, 0.2 * inch))

    table_data = [
        ["Field", "Value"],
        ["URL", scan_result.get("url", "")],
        ["Prediction", scan_result.get("prediction", "")],
        ["Confidence", f"{scan_result.get('confidence', 0)}%"],
        ["Risk Level", scan_result.get("risk_level", "")],
        ["Date & Time", scan_result.get("created_at", "")],
    ]

    table = Table(table_data, colWidths=[1.8 * inch, 4.8 * inch])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("Feature Analysis", title_style))
    feature_analysis = scan_result.get("feature_analysis", {})
    for key, value in feature_analysis.items():
        if isinstance(value, dict):
            story.append(Paragraph(f"• {key}: {value.get('value', '')}", body_style))
        else:
            story.append(Paragraph(f"• {key}: {value}", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer


def generate_history_pdf(scans):
    """Create a PDF document containing multiple scan records."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="Scan History Report")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=12,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=13,
        spaceAfter=6,
    )

    story = []
    story.append(Paragraph("Scan History Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 0.15 * inch))

    rows = [["URL", "Prediction", "Confidence", "Risk", "Date & Time"]]
    for scan in scans:
        rows.append([scan.get("url", ""), scan.get("prediction", ""), f"{scan.get('confidence', 0)}%", scan.get("risk_level", ""), scan.get("created_at", "")])

    table = Table(rows, colWidths=[2.4 * inch, 1.1 * inch, 0.9 * inch, 0.8 * inch, 1.4 * inch])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(table)

    doc.build(story)
    buffer.seek(0)
    return buffer

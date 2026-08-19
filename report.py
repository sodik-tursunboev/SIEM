"""
report.py
---------
Generates a PDF SOC summary report - the kind of thing a real analyst
hands to a manager or includes in a shift handoff. Covers a "daily" (last
24 hours) or "weekly" (last 7 days) window: totals, severity breakdown,
which rules fired most, which MITRE ATT&CK techniques showed up, and a
full table of every alert in the period.

Run directly:
    python report.py daily
    python report.py weekly

Or trigger it from the dashboard - see the "Generate Report" button,
which calls the /api/report/<period> route in app.py.
"""

import os
from datetime import datetime, timedelta
from collections import Counter

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

import database as db

import paths
REPORTS_DIR = paths.data_path("reports")

SEVERITY_COLOR = {
    "Critical": colors.HexColor("#B0294A"),
    "High": colors.HexColor("#C05A3E"),
    "Medium": colors.HexColor("#B8860B"),
    "Low": colors.HexColor("#2E6DA4"),
}


def _period_range(period: str):
    end = datetime.utcnow()
    if period == "weekly":
        start = end - timedelta(days=7)
    else:
        period = "daily"
        start = end - timedelta(hours=24)
    return period, start, end


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontSize=22, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor("#555555"), spaceAfter=18,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"], fontSize=13,
        spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1A1A2E"),
    ))
    return styles


def build_report(period: str = "daily") -> str:
    """Builds the PDF and returns the file path it was saved to."""
    period, start, end = _period_range(period)

    alerts = db.get_alerts_between(start.isoformat(), end.isoformat())
    logs = db.get_logs_between(start.isoformat(), end.isoformat())

    severity_counts = Counter(a["severity"] for a in alerts)
    rule_counts = Counter(a["rule_name"] for a in alerts)
    mitre_counts = Counter(
        (a["mitre_id"], a["mitre_technique"]) for a in alerts if a.get("mitre_id")
    )

    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"siem_report_{period}_{end.strftime('%Y-%m-%d_%H%M')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    styles = _styles()
    doc = SimpleDocTemplate(
        filepath, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    story = []

    # ---- Header ----
    story.append(Paragraph("Mini SIEM — SOC Summary Report", styles["ReportTitle"]))
    story.append(Paragraph(
        f"{period.capitalize()} report &nbsp;|&nbsp; "
        f"{start.strftime('%Y-%m-%d %H:%M')} UTC to {end.strftime('%Y-%m-%d %H:%M')} UTC "
        f"&nbsp;|&nbsp; Generated {end.strftime('%Y-%m-%d %H:%M')} UTC",
        styles["ReportSubtitle"],
    ))

    # ---- Summary numbers ----
    story.append(Paragraph("Summary", styles["SectionHeading"]))
    summary_data = [
        ["Total Logs Collected", str(len(logs))],
        ["Total Alerts", str(len(alerts))],
        ["Critical", str(severity_counts.get("Critical", 0))],
        ["High", str(severity_counts.get("High", 0))],
        ["Medium", str(severity_counts.get("Medium", 0))],
        ["Low", str(severity_counts.get("Low", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#DDDDDD")),
    ]))
    story.append(summary_table)

    # ---- Top rules triggered ----
    story.append(Paragraph("Top Rules Triggered", styles["SectionHeading"]))
    if rule_counts:
        rule_data = [["Rule", "Count"]] + [
            [rule, str(count)] for rule, count in rule_counts.most_common(10)
        ]
        rule_table = Table(rule_data, colWidths=[4.3 * inch, 1 * inch])
        rule_table.setStyle(_table_style_with_header())
        story.append(rule_table)
    else:
        story.append(Paragraph("No alerts in this period.", styles["Normal"]))

    # ---- MITRE ATT&CK coverage ----
    story.append(Paragraph("MITRE ATT&amp;CK Techniques Observed", styles["SectionHeading"]))
    if mitre_counts:
        mitre_data = [["Technique ID", "Technique Name", "Count"]] + [
            [tid, name, str(count)]
            for (tid, name), count in sorted(mitre_counts.items(), key=lambda x: -x[1])
        ]
        mitre_table = Table(mitre_data, colWidths=[1.2 * inch, 3.1 * inch, 1 * inch])
        mitre_table.setStyle(_table_style_with_header())
        story.append(mitre_table)
    else:
        story.append(Paragraph("No MITRE-tagged alerts in this period.", styles["Normal"]))

    # ---- Full alert log ----
    story.append(PageBreak())
    story.append(Paragraph(f"All Alerts ({len(alerts)})", styles["SectionHeading"]))
    if alerts:
        alert_rows = [["Time (UTC)", "Severity", "Rule", "User", "MITRE"]]
        for a in alerts:
            ts = a["timestamp"].replace("T", " ")[:19]
            alert_rows.append([
                ts, a["severity"], a["rule_name"],
                a["related_user"] or "-", a["mitre_id"] or "-",
            ])
        alert_table = Table(
            alert_rows,
            colWidths=[1.3 * inch, 0.75 * inch, 2.35 * inch, 0.9 * inch, 0.7 * inch],
            repeatRows=1,
        )
        style_cmds = _table_style_with_header()
        # color the severity column per-row
        for i, a in enumerate(alerts, start=1):
            color = SEVERITY_COLOR.get(a["severity"])
            if color:
                style_cmds.add("TEXTCOLOR", (1, i), (1, i), color)
                style_cmds.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
        alert_table.setStyle(style_cmds)
        story.append(alert_table)
    else:
        story.append(Paragraph("No alerts were raised during this period.", styles["Normal"]))

    doc.build(story)
    return filepath


def _table_style_with_header():
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#EEEEEE")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F9")]),
    ])


if __name__ == "__main__":
    import sys
    period = sys.argv[1] if len(sys.argv) > 1 else "daily"
    path = build_report(period)
    print(f"Report saved to: {path}")

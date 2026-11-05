from datetime import datetime, timezone
from html import escape
from pathlib import Path
from uuid import uuid4

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"

RED = colors.HexColor("#C62838")
BLACK = colors.HexColor("#151820")
GRAY = colors.HexColor("#667085")


def generate_incident_report(analysis):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report_id = uuid4().hex[:10].upper()
    report_path = REPORT_DIR / f"INC-{report_id}.pdf"

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=24,
        textColor=RED,
        spaceAfter=12
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=RED,
        spaceBefore=15,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=BLACK,
        splitLongWords=True
    ))

    body_style = styles["ReportBody"]
    story = []

    def add_text(value):
        story.append(
            Paragraph(
                escape(str(value)),
                body_style
            )
        )

    def add_section(title):
        story.append(
          Paragraph(escape(title), styles["SectionHeading"])
        )

    def add_details(rows):
        data = []

        for label, value in rows:
            data.append([
                Paragraph(
                    f"<b>{escape(str(label))}</b>",
                    body_style
                ),
                Paragraph(
                    escape(str(value)),
                    body_style
                )
            ])

        table = Table(
            data,
            colWidths=[115, 365],
            hAlign="LEFT"
        )

        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, GRAY)
        ]))

        story.append(table)

    rules = analysis["rule_based"]
    ml = analysis["machine_learning"]

    created = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    story.append(Paragraph(
        "PHISHING DETECTION SOC",
        styles["ReportTitle"]
    ))

    add_text("SECURITY INCIDENT ANALYSIS REPORT")
    story.append(Spacer(1, 10))

    add_details([
        ("Report ID", f"INC-{report_id}"),
        ("Generated", created),
        ("Assessment", analysis["final_assessment"]),
        ("Risk Level", rules["risk_level"]),
        ("Risk Score", f'{rules["risk_score"]}/100'),
        ("ML Prediction", ml["prediction"]),
        (
            "ML Probability",
            f'{ml["phishing_probability"] * 100:.2f}%'
        )
    ])

    add_section("1. Email Information")

    add_details([
        ("Sender", analysis.get("sender", "")),
        ("Subject", analysis.get("subject", ""))
    ])

    add_section("2. Detection Findings")

    findings = rules.get("reasons", [])

    if findings:
        for index, finding in enumerate(findings, 1):
            add_text(f"{index}. {finding}")
    else:
        add_text("No suspicious rule indicators detected.")

    add_section("3. URL Analysis")

    url_results = rules.get("url_analysis", [])

    if url_results:
        for item in url_results:
            add_text(
                f'URL: {item["url"]} | '
                f'Risk Score: {item["risk_score"]}/100'
            )
    else:
        add_text("No URLs detected.")

    add_section("4. Threat Intelligence")

    intelligence = analysis.get("threat_intelligence", [])

    if intelligence:
        for item in intelligence:
            add_text(
                f'{item["provider"]} | '
                f'{item["status"]} | '
                f'{item["url"]}'
            )
    else:
        add_text("No threat intelligence results.")

    add_section("5. Email Authentication")

    auth = rules.get("auth_results", {})

    add_details([
        ("SPF", auth.get("spf", "not_found")),
        ("DKIM", auth.get("dkim", "not_found")),
        ("DMARC", auth.get("dmarc", "not_found")),
        (
            "Trusted Source",
            str(rules.get("auth_trusted", False))
        )
    ])

    add_section("6. MITRE ATT&CK Mapping")

    add_details([
        ("Technique", "T1566"),
        ("Technique Name", "Phishing"),
        ("Tactic", "Initial Access")
    ])

    story.append(Spacer(1, 6))

    add_text(
        "This report contains an automated security assessment. "
        "Findings require analyst verification before incident confirmation."
    )

    doc.build(story)

    return str(report_path)

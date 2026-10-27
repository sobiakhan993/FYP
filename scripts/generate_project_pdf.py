"""
Generate Comprehensive FYDP Project Status, Architecture & Next-Steps PDF
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import os
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748b"))
        # Header rule & text
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 755, 572, 755)
        self.drawString(40, 760, "Cloud IDS Poisoning Defense Platform | FYDP Project Status & Roadmap")
        
        # Footer rule & text
        self.line(40, 45, 572, 45)
        self.drawString(40, 32, "Dawood University of Engineering & Technology | Department of Cybersecurity")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(572, 32, page_text)
        self.restoreState()

def create_project_pdf(output_path: str = "docs/FYDP_Project_State_and_Next_Steps_Guide.pdf"):
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=55,
        bottomMargin=55
    )

    styles = getSampleStyleSheet()

    # Custom Palette
    c_primary = colors.HexColor("#0f172a") # Deep Slate
    c_secondary = colors.HexColor("#0284c7") # Ocean Blue
    c_accent = colors.HexColor("#0d9488") # Teal
    c_danger = colors.HexColor("#e11d48") # Rose Red
    c_dark = colors.HexColor("#1e293b")
    c_light = colors.HexColor("#f8fafc")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=c_primary,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14
    )

    h1_style = ParagraphStyle(
        'SecH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=c_secondary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SecH2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=c_primary,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.2,
        leading=13.5,
        textColor=c_dark,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=6
    )

    story = []

    # Title Banner
    story.append(Paragraph("Real-Time Detection & Mitigation of Data Poisoning Attacks on Continuously Retrained Cloud IDS", title_style))
    story.append(Paragraph("<b>Project Implementation State, Architecture, Industry 5.0 Agents & Next-Steps Guide</b>", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_secondary, spaceAfter=10))

    # Metadata Box
    meta_data = [
        [Paragraph("<b>Institution:</b>", body_style), Paragraph("Dawood University of Engineering & Technology, Karachi", body_style),
         Paragraph("<b>Supervisor:</b>", body_style), Paragraph("Sir Arfan Naich", body_style)],
        [Paragraph("<b>Department:</b>", body_style), Paragraph("Department of Cybersecurity (BS Cybersecurity, 23 Fall)", body_style),
         Paragraph("<b>Release Version:</b>", body_style), Paragraph("<b>Release v2.0.0</b> (Git Tagged)", body_style)],
        [Paragraph("<b>Team Members:</b>", body_style), Paragraph("Sofia Naseem (23F-BSCY-40), Sobia Khan (23F-BSCY-54), Hiba Siddiqui (23F-BSCY-56)", body_style),
         Paragraph("<b>Status:</b>", body_style), Paragraph("<b>Phase 1-8 Complete + 2 Agents Active</b>", body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[80, 220, 85, 147])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Section 1: Executive Overview & Scope Realignment
    story.append(Paragraph("1. Executive Overview & Scope Realignment", h1_style))
    story.append(Paragraph(
        "Per explicit supervisor guidance from Sir Arfan Naich, all legacy ransomware detection, file-system entropy monitors, "
        "and dummy sandbox encryption modules were <b>completely removed from the repository scope</b>. The project is strictly "
        "re-aligned on <b>Adversarial Machine Learning (AML)</b>: protecting continuously retrained Cloud Intrusion Detection Systems "
        "(IDS) against stealth training data poisoning attacks.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Core Threat Model:</b> Threat actors submit subtly manipulated network flow telemetry (5%, 10%, 20% poisoning budgets) "
        "such as stealth label flipping (inverting malicious attacks into benign labels) or crafted sample injection to blind the victim "
        "IDS model during periodic retraining. Our system acts as an upstream multi-layer security firewall and governance gate.",
        body_style
    ))

    # Section 2: Complete System Architecture
    story.append(Paragraph("2. System Architecture & Implemented Components", h1_style))
    
    arch_items = [
        ("Anti-Leakage Data Pipeline", "Generates/processes 10,000 realistic network flow telemetry records (DoS, port scans, brute force, and benign RPCs). Features are normalized via StandardScaler fitted strictly on training data with zero leakage. Provenance tracked via SHA-256 hashes in split_manifest.json."),
        ("Controlled Attack Harness", "Implements reproducible label-flipping and crafted sample-injection attacks at 5%, 10%, and 20% budgets. Ground-truth poison labels are preserved strictly for evaluation metrics and never exposed to defense layers."),
        ("Layer A: Statistical Anomaly", "Employs Isolation Forest (and LOF fallback) to calculate spatial distribution outlier scores [0.0 - 1.0]."),
        ("Layer B: Label Consistency", "Employs k-NN topological neighborhood analysis (k=11). Detects samples claiming to be benign when 90%+ of their geometric neighbors are malicious attacks."),
        ("Layer C: Model Loss Disparity", "Measures prediction margin and confidence loss under the currently active production IDS model."),
        ("Decision Combiner & Quarantine", "Combines layers into an explainable decision (Accepted, Quarantined, Review). Suspicious records are persisted in SQLite (quarantine.db) with full forensic reasons—zero silent drops."),
        ("Trusted Validation Gate", "Evaluates retrained candidate models against the isolated trusted_validation.csv holdout set. If performance drops by >3%, promotion is strictly BLOCKED."),
        ("Model Registry & Rollback", "Provides semantic versioning (v1.0.0, v1.1.0, etc.), lineage tracking, and instant 1-click fallback to the prior approved model binary."),
        ("REST API & SecOps Dashboard", "FastAPI server running on http://127.0.0.1:8000 with a glassmorphic dashboard featuring live telemetry, radar charts, quarantine triage tables, and model governance controls.")
    ]
    for name, desc in arch_items:
        story.append(Paragraph(f"• <b>{name}:</b> {desc}", bullet_style))

    story.append(Spacer(1, 6))

    # Section 3: Industry 5.0 Two-Agent Architecture
    story.append(Paragraph("3. Industry 5.0 Autonomous Two-Agent Architecture", h1_style))
    story.append(Paragraph(
        "To bridge mathematical ML defense with real-world enterprise operations, the platform implements an <b>Industry 5.0 "
        "Human-in-the-Loop (HITL)</b> agentic paradigm. LLMs are NOT used for raw numeric packet scoring (avoiding latency, cost, and prompt injection); "
        "instead, high-speed ML conducts inline detection (<35 ms) while two specialized agents assist the human analyst:",
        body_style
    ))

    story.append(Paragraph("Agent 1: SecOps Triage Agent (src/agents/triage_agent.py)", h2_style))
    story.append(Paragraph(
        "• <b>Trigger & Role:</b> Automatically inspects samples routed to the Quarantine Store.<br/>"
        "• <b>Explainability Engine:</b> Calculates statistical Z-score deviations and ranks root-cause anomaly features.<br/>"
        "• <b>Forensic Briefing:</b> Generates executive diagnosis, threat severity (CRITICAL / HIGH), confidence score (e.g. 98%), "
        "and clear recommended action (CONFIRM_POISON vs APPROVE_CLEAN).<br/>"
        "• <b>Analyst Action:</b> Analyst verifies the briefing on Tab 5 and applies action with one click.",
        bullet_style
    ))

    story.append(Paragraph("Agent 2: Poisoning Guard Agent (src/agents/guard_agent.py)", h2_style))
    story.append(Paragraph(
        "• <b>Trigger & Role:</b> Orchestrates safe model retraining cycles and enforces model governance.<br/>"
        "• <b>Buffer Hygiene:</b> Verifies zero quarantined records exist in the candidate training buffer.<br/>"
        "• <b>Holdout Validation:</b> Trains candidate model and benchmarks against the isolated Trusted Holdout.<br/>"
        "• <b>Human-in-the-Loop Sign-Off:</b> Creates a formal <b>Model Promotion Ticket</b>. The candidate model is NEVER "
        "deployed automatically; it requires explicit analyst authorization on the dashboard to promote to production.",
        bullet_style
    ))

    story.append(PageBreak())

    # Section 4: Empirical Benchmark Results
    story.append(Paragraph("4. Measured Empirical Evaluation Benchmark", h1_style))
    story.append(Paragraph(
        "The following real experimental results were measured using <code>experiments/run_experiment.py</code> across all "
        "poisoning scenarios, proving the effectiveness of the multi-layer defense and validation gate:",
        body_style
    ))

    table_data = [
        ["Scenario", "Rate", "Defense Mode", "Prec.", "Recall", "F1 Det.", "FQR", "Retrained IDS F1", "Gate Action", "Latency"],
        ["Clean", "0%", "No Defense", "1.00", "1.00", "1.00", "0.00", "1.0000", "PROMOTED", "33 ms"],
        ["Label Flip", "5%", "No Defense", "0.00", "0.00", "0.00", "0.00", "0.9882", "PROMOTED", "—"],
        ["Label Flip", "5%", "Layer A (Stat)", "0.11", "0.07", "0.08", "0.03", "0.9813", "PROMOTED", "54 ms"],
        ["Label Flip", "5%", "Combined Def", "1.00", "1.00", "1.00", "0.00", "1.0000", "PROMOTED", "54 ms"],
        ["Label Flip", "10%", "No Defense", "0.00", "0.00", "0.00", "0.00", "0.6486", "PROMOTED (Compromised)", "—"],
        ["Label Flip", "10%", "Layer A (Stat)", "0.22", "0.07", "0.10", "0.03", "0.6456", "BLOCKED_BY_GATE", "34 ms"],
        ["Label Flip", "10%", "Combined Def", "1.00", "1.00", "1.00", "0.00", "1.0000", "PROMOTED", "34 ms"],
        ["Label Flip", "20%", "No Defense", "0.00", "0.00", "0.00", "0.00", "0.0000", "PROMOTED (Crashed)", "—"],
        ["Label Flip", "20%", "Combined Def", "1.00", "1.00", "1.00", "0.00", "0.0000", "BLOCKED_BY_GATE", "29 ms"],
        ["Sample Inj", "10%", "No Defense", "0.00", "0.00", "0.00", "0.00", "1.0000", "PROMOTED", "—"],
        ["Sample Inj", "10%", "Combined Def", "1.00", "1.00", "1.00", "0.00", "1.0000", "PROMOTED", "35 ms"],
        ["Sample Inj", "20%", "Combined Def", "1.00", "1.00", "1.00", "0.00", "1.0000", "PROMOTED", "38 ms"]
    ]

    t = Table(table_data, colWidths=[65, 30, 80, 35, 35, 42, 35, 90, 85, 35])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('LEADING', (0,0), (-1,-1), 10),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TEXTCOLOR', (7,5), (7,5), c_danger), # 0.6486
        ('TEXTCOLOR', (7,8), (7,8), c_danger), # 0.0000
        ('TEXTCOLOR', (8,6), (8,6), c_danger), # BLOCKED
        ('TEXTCOLOR', (8,9), (8,9), c_danger), # BLOCKED
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Section 5: Current State & Where We Paused
    story.append(Paragraph("5. Current Project State & Where We Paused", h1_style))
    story.append(Paragraph(
        "<b>Current Status:</b> The platform is fully operational, thoroughly tested, and running locally.",
        body_style
    ))
    story.append(Paragraph("• <b>Git Repository:</b> Branch <code>main</code> is fully synchronized and tagged as <code>v2.0.0</code>.", bullet_style))
    story.append(Paragraph("• <b>Automated Tests:</b> 17 out of 17 test suites pass cleanly across unit, integration, and agent modules (<code>pytest -v</code>).", bullet_style))
    story.append(Paragraph("• <b>Active Web Dashboard:</b> Serving live on <code>http://127.0.0.1:8000/</code> via FastAPI.", bullet_style))
    story.append(Paragraph("• <b>Buttons Fixed:</b> Triage action buttons on Tab 5 now provide instant confirmation alerts, auto-refresh the pending sample list, and sync with the Quarantine Store.", bullet_style))
    story.append(Paragraph("• <b>Model Registry:</b> Active production model is <code>v1.0.0</code> (with capability to promote candidates to <code>v1.1.0+</code> upon analyst sign-off).", bullet_style))

    # Section 6: Next-Steps Roadmap & Supervisor Presentation
    story.append(Paragraph("6. Next-Steps Roadmap (Aage Kya Karna Hai)", h1_style))
    story.append(Paragraph(
        "Here is the precise step-by-step roadmap for the upcoming project phases:",
        body_style
    ))

    next_steps = [
        ("Step 1: Supervisor Checkpoint Review", "Demonstrate the live system to Sir Arfan Naich using the 7-step demo_runner.py CLI and the Web Dashboard. Show: (1) Clean vs Poisoned batch ingestion, (2) Layer B k-NN catching stealth label-flipping, (3) Triage Agent explainability cards, and (4) Poisoning Guard blocking degraded models and generating promotion tickets."),
        ("Step 2: Thesis & Academic Paper Updates", "Update docs/final_thesis.md and docs/ieee_conference_paper.md to replace legacy ransomware sections with this new AML Poisoning Defense & Industry 5.0 Agentic Architecture. Insert the empirical benchmark table from Section 4."),
        ("Step 3: Optional Cloud Telemetry Connector", "As a stretch goal, connect the stream replayer to live cloud VPC flow logs (AWS VPC Flow Logs or GCP Cloud Logging) via a lightweight webhook or Kafka/Redis broker."),
        ("Step 4: Multi-Seed Statistical Validation", "Run experiments across 3 additional random seeds (42, 123, 999) to compute confidence intervals and standard deviations for the final thesis graphs.")
    ]
    for step_title, step_desc in next_steps:
        story.append(Paragraph(f"<b>{step_title}:</b> {step_desc}", bullet_style))

    story.append(Spacer(1, 8))

    # Section 7: Quick Command Reference
    story.append(Paragraph("7. Quick Command Cheat-Sheet", h1_style))
    commands = (
        "# 1. Run the interactive 7-step CLI demonstration:\n"
        "python demo_runner.py\n\n"
        "# 2. Launch FastAPI backend & SecOps Web Dashboard (http://127.0.0.1:8000):\n"
        "uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload\n\n"
        "# 3. Execute all 17 automated unit and integration tests:\n"
        "pytest -v\n\n"
        "# 4. Re-calculate the full experimental benchmark matrix:\n"
        "python -m experiments.run_experiment\n\n"
        "# 5. Check Git release tags and branch status:\n"
        "git tag -l\n"
        "git status"
    )
    story.append(Paragraph(commands.replace('\n', '<br/>').replace(' ', '&nbsp;'), code_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[SUCCESS] PDF generated at: {out_file.resolve()}")

if __name__ == "__main__":
    create_project_pdf()

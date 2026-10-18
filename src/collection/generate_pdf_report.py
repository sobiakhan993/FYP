"""
PDF Report Generator for Real-World Cloud Production Deployment Guide
Generates a formal, beautifully formatted multi-page PDF document using ReportLab.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

PDF_OUTPUT_PATH = os.path.abspath('docs/Real_World_Cloud_Deployment_Guide.pdf')

class NumberedCanvas(canvas.Canvas):
    """Canvas that enables two-pass page numbering: 'Page X of Y'"""
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
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#6B7280"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "Cloud Defense Sentinel — Real-World Cloud Deployment Guide")
            self.drawRightString(612 - 54, 750, "DUET BS Cybersecurity FYDP")
            self.setStrokeColor(colors.HexColor("#E5E7EB"))
            self.setLineWidth(0.5)
            self.line(54, 742, 612 - 54, 742)
            
        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 36, footer_text)
        self.drawString(54, 36, "Confidential — Academic & Technical Architecture Report")
        self.setStrokeColor(colors.HexColor("#E5E7EB"))
        self.setLineWidth(0.5)
        self.line(54, 48, 612 - 54, 48)
        self.restoreState()

def build_pdf_report():
    os.makedirs(os.path.dirname(PDF_OUTPUT_PATH), exist_ok=True)
    doc = SimpleDocTemplate(
        PDF_OUTPUT_PATH,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Palette
    primary_color = colors.HexColor("#0F172A")    # Deep Navy
    accent_blue = colors.HexColor("#1E40AF")      # Royal Blue
    accent_teal = colors.HexColor("#0D9488")      # Teal / Cyan
    text_dark = colors.HexColor("#1F2937")        # Dark Gray
    text_muted = colors.HexColor("#4B5563")       # Muted Gray
    bg_light = colors.HexColor("#F8FAFC")         # Very light slate
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=primary_color,
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=accent_blue,
        spaceAfter=15
    )
    
    meta_style = ParagraphStyle(
        'MetaText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=text_muted
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=accent_teal,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=text_dark,
        spaceAfter=8
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=text_dark,
        leftIndent=15,
        spaceAfter=4
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=primary_color
    )

    story = []

    # ----------------- COVER & HEADER -----------------
    story.append(Paragraph("REAL-WORLD CLOUD PRODUCTION DEPLOYMENT & ROADMAP", title_style))
    story.append(Paragraph("A Technical Engineering Guide for Transitioning Ransomware & Poisoning Attack Detection into AWS, Azure, & Enterprise Multi-Cloud Environments", subtitle_style))
    
    meta_info = """
    <b>Institution:</b> Dawood University of Engineering & Technology (DUET), Karachi<br/>
    <b>Department:</b> Department of Cybersecurity, Faculty of Information & Computing Sciences<br/>
    <b>Project:</b> BS Cybersecurity Final Year Design Project (FYDP)<br/>
    <b>Supervisor:</b> Sir Arfan Naich<br/>
    <b>Group Members:</b> Sofia Naseem (23F-BSCY-40), Sobia Khan (23F-BSCY-54), Hiba Siddiqui (23F-BSCY-56)
    """
    story.append(Paragraph(meta_info, meta_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceAfter=15))

    # ----------------- SECTION 1 -----------------
    story.append(Paragraph("1. Executive Overview: Transitioning from Prototype to Production", h1_style))
    story.append(Paragraph(
        "The prototype developed in FYDP Phases 1 through 10 establishes a functional dual-engine detection architecture combining supervised classification (Random Forest) with unsupervised anomaly scoring (Isolation Forest) and an upstream data poisoning defense gate. To transition this system into an enterprise-grade cloud security product (e.g. AWS, Microsoft Azure, Google Cloud), the architecture must scale across hundreds of virtual instances, interface with distributed storage buckets, ingest real operational telemetry, and execute automated active containment.",
        body_style
    ))

    # ----------------- SECTION 2 -----------------
    story.append(Paragraph("2. Real-World Telemetry Agent Architecture", h1_style))
    story.append(Paragraph(
        "In production cloud environments, threat monitoring requires multi-layer telemetry capture spanning host virtual machines, containerized workloads, and cloud-native object storage services.",
        body_style
    ))
    
    story.append(Paragraph("A. Host Workload Telemetry (Virtual Machines & Containers)", h2_style))
    story.append(Paragraph("• <b>Lightweight Python Daemon (systemd / Windows Service):</b> The collector engineered in Phase 5 (<code>src/monitoring/host_collector.py</code>) can be compiled into a standalone service running with least-privilege permissions. It hooks filesystem writes, calculates Shannon Entropy ($E > 7.5$), and captures CPU/disk I/O with &lt; 2% processor utilization.", bullet_style))
    story.append(Paragraph("• <b>Linux eBPF (Extended Berkeley Packet Filter):</b> For high-throughput cloud environments, eBPF programs trace kernel-level system calls (<code>sys_enter_write</code>, <code>vfs_write</code>) without modifying kernel source, ensuring zero overhead and immune to user-space tampering.", bullet_style))
    story.append(Paragraph("• <b>Microsoft Sysmon (Windows Server Instances):</b> Captures Event ID 11 (FileCreate), Event ID 2 (File creation time changes), and process tree anomalies, feeding directly into the ingestion queue.", bullet_style))

    story.append(Paragraph("B. Cloud-Native Storage & Management Plane (S3, Blob, Audit Logs)", h2_style))
    story.append(Paragraph("• <b>AWS CloudTrail & Azure Activity Logs:</b> Monitors management plane API calls, detecting unauthorized snapshot deletion, backup purge attempts, and IAM credential compromise.", bullet_style))
    story.append(Paragraph("• <b>Amazon EventBridge & S3 Event Notifications:</b> Tracks bulk object alterations or mass deletions within Amazon S3 or Azure Blob Storage, triggering the feature extraction pipeline when suspicious modification rates occur.", bullet_style))

    # ----------------- SECTION 3 -----------------
    story.append(Paragraph("3. Real-World Model Training & Dataset Engineering", h1_style))
    story.append(Paragraph(
        "To achieve state-of-the-art generalization in commercial cloud environments, model training must advance from synthetic datasets to real-world operational distributions.",
        body_style
    ))
    story.append(Paragraph("• <b>Step 3.1: 3-to-5 Day Normal Baseline Collection:</b> Deploy the collector daemon across staging cloud servers running genuine enterprise workloads (e.g., Nginx web servers, PostgreSQL databases, CI/CD runners). This captures authentic baseline entropy (~3.5 bits/byte), diurnal modification cycles, and routine backup archiving, establishing a clean baseline that eliminates false positives.", bullet_style))
    story.append(Paragraph("• <b>Step 3.2: Integrating Public Malware Corpora:</b> Incorporate dynamic execution traces from recognized academic benchmarks including the <b>UGRansome Dataset</b> (Locky, Cerber, WannaCry traces), <b>RanSMAP</b> (API dynamic call logs), and <b>CIC-IDS2017</b>.", bullet_style))
    story.append(Paragraph("• <b>Step 3.3: Safe Detonation via Automated Sandboxes:</b> Rather than executing live malware on internal networks, subscribe to automated analysis sandboxes (e.g. <b>Hybrid-Analysis</b>, <b>Any.Run</b>, or private Cuckoo Sandboxes). Download behavioral JSON execution reports for emerging ransomware variants (e.g. LockBit 3.0, BlackCat) and translate their disk I/O metrics into our standard 10-feature vector format.", bullet_style))

    story.append(PageBreak())

    # ----------------- SECTION 4 -----------------
    story.append(Paragraph("4. Scalable Centralized Streaming Pipeline (Multi-Instance Ingestion)", h1_style))
    story.append(Paragraph(
        "Commercial deployments cannot rely on local inter-process pipes. When monitoring dozens or hundreds of cloud instances simultaneously, telemetry must flow through a resilient, decoupled message broker.",
        body_style
    ))
    
    # Architecture diagram / box
    diag_data = [
        [Paragraph("<b>Centralized Multi-Instance Cloud Pipeline</b>", h2_style)],
        [Paragraph("<b>Monitored Instances:</b> [EC2 VM-01] [EC2 VM-02] ... [EC2 VM-N] + [Amazon S3 Buckets]<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│ (TLS-Encrypted JSON Telemetry Stream)<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
                   "<b>Message Broker:</b> Amazon SQS (Simple Queue Service) or Apache Kafka / Redis Streams<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│ (Batch Consumer & 60-Second Sliding Windows)<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
                   "<b>Dual-Engine Inference Engine:</b> Random Forest + Isolation Forest (Inference Latency &lt; 35 ms)<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;┌───────────────┴───────────────┐<br/>"
                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼                               ▼<br/>"
                   "<b>SecOps Dashboard & Alerts</b> (SSE / WebSockets) &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <b>Automated Containment</b> (AWS Boto3)", meta_style)]
    ]
    diag_table = Table(diag_data, colWidths=[504])
    diag_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(diag_table)
    story.append(Spacer(1, 10))

    # ----------------- SECTION 5 -----------------
    story.append(Paragraph("5. Automated Incident Response & Active Containment (SOAR)", h1_style))
    story.append(Paragraph(
        "In production environments, passive alerting is insufficient because ransomware can encrypt thousands of files before a human analyst responds. The system must execute automated micro-containment:",
        body_style
    ))
    story.append(Paragraph("• <b>Immediate Network Isolation via Cloud SDKs:</b> Upon receiving a CRITICAL alert from the Score Combiner ($P_{rf} &gt; 0.85$), the platform executes an automated API call using the cloud SDK (e.g. <code>boto3</code> for AWS). It re-associates the affected EC2 instance with an isolated 'Quarantine' Security Group, severing all ingress/egress network connections and halting lateral malware spread.", bullet_style))
    story.append(Paragraph("• <b>Automated EBS Snapshot Preservation:</b> Instantly triggers an AWS EBS Volume snapshot. This preserves cryptographic evidence, memory state, and original files for subsequent forensic decryption analysis.", bullet_style))
    story.append(Paragraph("• <b>Multi-Channel Notification Dispatch:</b> Emits high-priority webhooks to corporate Slack security channels, PagerDuty incident queues, and SMS/Email alerts via Amazon SNS.", bullet_style))

    # ----------------- SECTION 6 -----------------
    story.append(Paragraph("6. Continuous Upstream Poisoning Defense in Staging", h1_style))
    story.append(Paragraph(
        "To protect continuous model retraining in production against adversarial manipulation (label-flipping or clean-label backdoors):",
        body_style
    ))
    story.append(Paragraph("• <b>Air-Gapped Staging Retraining Pipeline:</b> Never retrain production models directly on unverified live streams. Incoming telemetry must accumulate in an isolated staging database.", bullet_style))
    story.append(Paragraph("• <b>Multi-Stage Defensive Sanitization:</b> Execute the Phase 7 sanitizer module. Run k-NN neighborhood consistency checks (k=5) and Local Outlier Factor (LOF) spatial density filtering. Flagged anomalous records are routed to the <code>quarantine_store</code> database table for SecOps audit.", bullet_style))
    story.append(Paragraph("• <b>Automated Hold-Out Validation Regression Gate:</b> The candidate retrained model is evaluated against a locked, golden validation partition (<code>trusted_validation.csv</code>). If the validation F1-score falls below 95% or degrades by more than 2% ($\Delta F_1 &gt; 0.02$), deployment is automatically blocked and an administrative security alert is raised.", bullet_style))

    # ----------------- SECTION 7 -----------------
    story.append(Spacer(1, 10))
    story.append(Paragraph("7. Actionable Implementation Checklist for Cloud Production", h1_style))
    
    table_data = [
        [Paragraph("<b>Step</b>", meta_style), Paragraph("<b>Production Action</b>", meta_style), Paragraph("<b>Target Tool / Technology</b>", meta_style), Paragraph("<b>Key Security Outcome</b>", meta_style)],
        [Paragraph("<b>1</b>", meta_style), Paragraph("Host Agent Packaging", meta_style), Paragraph("Linux systemd daemon / eBPF", meta_style), Paragraph("Continuous low-overhead VM telemetry", meta_style)],
        [Paragraph("<b>2</b>", meta_style), Paragraph("Object Storage Hooks", meta_style), Paragraph("AWS EventBridge & CloudTrail", meta_style), Paragraph("Detects mass S3 bucket encryption", meta_style)],
        [Paragraph("<b>3</b>", meta_style), Paragraph("Central Event Broker", meta_style), Paragraph("Amazon SQS / Apache Kafka", meta_style), Paragraph("Scalable multi-VM stream buffering", meta_style)],
        [Paragraph("<b>4</b>", meta_style), Paragraph("Real Baseline Profiling", meta_style), Paragraph("3-5 Day Staging EC2 Recording", meta_style), Paragraph("Establishes authentic zero-FPR profile", meta_style)],
        [Paragraph("<b>5</b>", meta_style), Paragraph("Active Containment", meta_style), Paragraph("AWS Boto3 API Security Groups", meta_style), Paragraph("Instant automatic network quarantine", meta_style)],
        [Paragraph("<b>6</b>", meta_style), Paragraph("Retraining Gate", meta_style), Paragraph("k-NN + LOF + Validation Gate", meta_style), Paragraph("Guarantees model self-protection", meta_style)],
    ]
    
    plan_table = Table(table_data, colWidths=[36, 140, 164, 164])
    plan_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, bg_light]),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(plan_table)
    
    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated production PDF report: {PDF_OUTPUT_PATH}")

if __name__ == '__main__':
    build_pdf_report()

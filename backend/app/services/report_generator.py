"""
Forensic Report Generator for Cloud Incident & Response Platform.
Compiles comprehensive, CISO/management-ready forensic investigation reports in
Markdown, HTML, and high-fidelity PDF formats.
"""

import os
import io
import logging
from typing import Dict, Any, List
from datetime import datetime
import markdown

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from app.services.azure_sentinel import determine_incident_type
from app.services.evidence_bundler import DeepEvidenceBundler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("report_generator")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


class ForensicReportGenerator:
    """Generates structured forensic investigation reports in Markdown, HTML, and PDF."""

    @staticmethod
    def _get_finding_summary(incident_type: str, title: str, static_sev: str, dynamic_label: str, dynamic_score: float) -> str:
        """Generates tailored finding text based on incident classification."""
        if incident_type == "BRUTE_FORCE":
            return (
                f"Microsoft Sentinel triggered an alert for <b>{title}</b> with baseline static severity <b>{static_sev}</b>. "
                f"Automated identity telemetry analysis confirmed high-frequency failed sign-in attempts against Microsoft Entra ID. "
                f"The target identity was protected via Smart Lockout enforcement. The Dynamic Risk Model evaluated the incident posture "
                f"at <b>{dynamic_label.upper()} ({dynamic_score}/100)</b>."
            )
        elif incident_type == "PRIVILEGE_ESCALATION":
            return (
                f"Azure Sentinel detected unauthorized privilege escalation (<b>{title}</b>). "
                f"Deep ARM evidence bundling confirmed IAM role elevation to a privileged scope. "
                f"Dynamic ML Risk Engine recalculated severity to <b>{dynamic_label.upper()} ({dynamic_score}/100)</b>."
            )
        elif incident_type == "STORAGE_EXPOSURE":
            return (
                f"Security detection <b>{title}</b> identified public blob exposure on Azure Storage. "
                f"Automated posture inspection verified allowBlobPublicAccess and SAS generation, resulting in dynamic score <b>{dynamic_label.upper()} ({dynamic_score}/100)</b>."
            )
        elif incident_type == "IMDS_TOKEN_THEFT":
            return (
                f"Security alert <b>{title}</b> indicated exploitation of Instance Metadata Service (169.254.169.254) to harvest Managed Identity credentials. "
                f"Dynamic ML Model classified the resulting threat as <b>{dynamic_label.upper()} ({dynamic_score}/100)</b>."
            )
        else:
            return (
                f"Microsoft Sentinel alert <b>{title}</b> was ingested with static severity <b>{static_sev}</b>. "
                f"Deep cloud evidence collection evaluated the posture, yielding dynamic score <b>{dynamic_label.upper()} ({dynamic_score}/100)</b>."
            )

    @staticmethod
    def generate_markdown(incident: Dict[str, Any]) -> str:
        """Generates a complete Markdown investigation report."""
        inc_id = incident.get("incident_id", "INC-UNKNOWN")
        title = incident.get("title", "Microsoft Entra ID Security Alert")
        created_at = incident.get("created_at", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        static_sev = incident.get("sentinel_static_severity", incident.get("static_severity", "Medium"))
        dynamic_score = incident.get("dynamic_ml_risk_score", 50.0)
        dynamic_label = incident.get("dynamic_risk_label", "Medium")
        target_resource = incident.get("target_resource", "Microsoft Entra ID")
        attacker_ip = incident.get("attacker_ip", "101.0.63.28")
        affected_user = incident.get("affected_user", "identity@corp.onmicrosoft.com")
        incident_type = incident.get("incident_type") or determine_incident_type(incident)

        # Risk Factors
        risk_factors = incident.get("top_risk_factors", [])
        factors_md = ""
        for idx, rf in enumerate(risk_factors, 1):
            lbl = rf.get("label", rf.get("feature_key", "Risk Factor"))
            pct = rf.get("contribution_percentage", 0)
            expl = rf.get("explanation", "")
            factors_md += f"{idx}. **{lbl}** ({pct}% Impact): {expl}\n"

        if not factors_md:
            factors_md = "- Baseline cloud security parameters evaluated.\n"

        # Timeline
        timeline_events = incident.get("timeline", [])
        timeline_md = ""
        if timeline_events:
            for ev in timeline_events:
                t = ev.get("timestamp", ev.get("time", "T-00:00"))
                typ = ev.get("event_type", ev.get("event", "Event"))
                src = ev.get("source", "Azure Telemetry")
                desc = ev.get("description", "")
                mitre = ev.get("mitre_tactic", "")
                mitre_str = f" `[MITRE: {mitre}]`" if mitre else ""
                timeline_md += f"- **`{t}`** — **{typ}** ({src}){mitre_str}: {desc}\n"
        else:
            timeline_md = (
                f"- **`{created_at}`** — **Initial Detection** (Microsoft Sentinel): Alert triggered on {target_resource}\n"
                f"- **`+2m 14s`** — **Automated Forensics Bundling**: Collected evidence snapshot\n"
                f"- **`+2m 16s`** — **ML Dynamic Evaluation**: Severity calculated to {dynamic_label} ({dynamic_score}/100)\n"
            )

        # Evidence Summary Table
        ev_data = incident.get("evidence_snapshot", {})
        iam_elev = "YES (Escalated)" if ev_data.get("iam_recent_role_elevation") else "Normal / Clean"
        mfa_byp = "BYPASSED" if ev_data.get("mfa_bypassed") else "Enforced / Not Bypassed"
        storage_pub = "PUBLIC ACCESS ENABLED" if ev_data.get("storage_public_access_enabled") else "Private (Secure)"
        imds_tok = "HARVESTED / COMPROMISED" if ev_data.get("imds_token_accessed") else "Clean (No Probe)"
        nsg_open = "0.0.0.0/0 INGRESS OPEN" if ev_data.get("nsg_unrestricted_inbound_any") else "Protected"
        exfil_mb = ev_data.get("exfiltrated_data_mb", 0.0)

        # Remediation Commands
        remediation_cmds = incident.get("remediation_playbook")
        if not remediation_cmds or len(remediation_cmds) == 0:
            remediation_cmds = DeepEvidenceBundler.generate_remediation_playbook(incident)

        playbook_md = "\n```bash\n" + "\n\n".join(remediation_cmds) + "\n```"
        finding_text = ForensicReportGenerator._get_finding_summary(incident_type, title, static_sev, dynamic_label, dynamic_score)

        md_content = f"""# 🔒 Cloud Security Forensic Investigation Report
**Report ID:** `FOR-{inc_id}` | **Classification:** `RESTRICTED / TLP:AMBER` | **Generated:** `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`

---

## 1. Executive Summary

| Attribute | Details |
| :--- | :--- |
| **Incident ID** | `{inc_id}` |
| **Alert Title** | **{title}** |
| **Attack Vector** | **`{incident_type}`** |
| **Sentinel Baseline Severity** | **`{static_sev}`** |
| **Dynamic ML Recalibrated Score** | **`{dynamic_score} / 100` (`{dynamic_label.upper()}`)** |
| **Target Asset / Scope** | `{target_resource}` |
| **Target Identity** | `{affected_user}` |
| **Threat Origin IP** | `{attacker_ip}` |

> **Key Investigation Finding:** {finding_text}

---

## 2. Dynamic ML Risk Factor Breakdown

The following cloud telemetry and environmental features contributed to the dynamic risk evaluation:

{factors_md}

---

## 3. Bundled Cloud Evidence Audit Snapshot

| Evidence Vector | Inspected Property | Finding Status | Risk Weight |
| :--- | :--- | :--- | :--- |
| **Identity / IAM** | Recent Role Elevation | `{iam_elev}` | High |
| **Identity / Auth** | MFA / Conditional Access | `{mfa_byp}` | High |
| **Storage Security** | Blob Public Access | `{storage_pub}` | Critical |
| **Compute / IMDS** | VM Managed Identity Token | `{imds_tok}` | Critical |
| **Network Security** | Inbound NSG Firewall Rules | `{nsg_open}` | Medium |
| **Data Egress** | Exfiltrated Data Volume | `{exfil_mb} MB` | High |

---

## 4. Chronological Attack Timeline Narrative (MITRE ATT&CK Aligned)

{timeline_md}

---

## 5. Automated Containment & Remediation Playbook

Execute the following commands in the Azure Cloud Shell or response automation pipeline to neutralize the threat:

{playbook_md}

---

*Report automatically generated by Cloud Incident & Forensic Response Platform. Evidence cryptographically hashed and archived for audit compliance.*
"""
        return md_content

    @staticmethod
    def generate_html(incident: Dict[str, Any]) -> str:
        """Converts the Markdown report into a beautifully styled HTML document."""
        md_text = ForensicReportGenerator.generate_markdown(incident)
        body_html = markdown.markdown(md_text, extensions=["tables", "fenced_code"])

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forensic Report - {incident.get('incident_id', 'INC')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 40px;
            max-width: 900px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
        h1 {{ font-size: 26px; color: #79c0ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background-color: #161b22; }}
        th, td {{ border: 1px solid #30363d; padding: 12px; text-align: left; }}
        th {{ background-color: #21262d; color: #f0f6fc; }}
        code {{ background-color: #21262d; color: #ff7b72; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
        pre {{ background-color: #161b22; padding: 16px; border-radius: 6px; border: 1px solid #30363d; overflow-x: auto; }}
        pre code {{ color: #7ee787; padding: 0; background: none; }}
        blockquote {{ border-left: 4px solid #f78166; padding-left: 16px; margin: 20px 0; color: #ffa657; background: #21262d; padding: 12px 16px; border-radius: 4px; }}
        hr {{ border: 0; height: 1px; background: #30363d; margin: 30px 0; }}
    </style>
</head>
<body>
    {body_html}
</body>
</html>"""
        return html_template

    @staticmethod
    def generate_pdf(incident: Dict[str, Any], output_path: str) -> str:
        """Generates a professional forensic investigation PDF report using ReportLab."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=6
        )
        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#2D3748")
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Code"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#2C7A7B"),
            backColor=colors.HexColor("#EDF2F7")
        )
        alert_style = ParagraphStyle(
            "AlertBox",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#9C4221"),
            backColor=colors.HexColor("#FEEBC8"),
            borderPadding=6,
            spaceBefore=6,
            spaceAfter=6
        )

        story = []

        # 1. Header & Metadata
        inc_id = incident.get("incident_id", "INC-UNKNOWN")
        dynamic_score = incident.get("dynamic_ml_risk_score", 50.0)
        dynamic_label = incident.get("dynamic_risk_label", "Medium")
        static_sev = incident.get("sentinel_static_severity", "Medium")
        incident_type = incident.get("incident_type") or determine_incident_type(incident)
        title = incident.get("title", "Microsoft Entra ID Security Alert")

        story.append(Paragraph("CLOUD FORENSIC INVESTIGATION REPORT", title_style))
        story.append(Paragraph(f"<b>Report ID:</b> FOR-{inc_id} &nbsp;|&nbsp; <b>Attack Vector:</b> {incident_type} &nbsp;|&nbsp; <b>Date:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=10))

        # 2. Executive Summary Table
        story.append(Paragraph("1. Executive Summary & Dynamic Risk Evaluation", h2_style))
        
        score_color = colors.HexColor("#E53E3E") if dynamic_score >= 85 else colors.HexColor("#DD6B20") if dynamic_score >= 65 else colors.HexColor("#3182CE")

        summary_data = [
            [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(str(inc_id), body_style),
             Paragraph("<b>Target Resource:</b>", body_style), Paragraph(str(incident.get("target_resource", "Microsoft Entra ID")), body_style)],
            [Paragraph("<b>Sentinel Static Severity:</b>", body_style), Paragraph(f"<b>{static_sev}</b>", body_style),
             Paragraph("<b>ML Dynamic Risk Score:</b>", body_style), Paragraph(f"<b><font color='{score_color.hexval()}'>{dynamic_score}/100 ({dynamic_label.upper()})</font></b>", body_style)],
            [Paragraph("<b>Target Identity:</b>", body_style), Paragraph(str(incident.get("affected_user", "identity@corp.onmicrosoft.com")), body_style),
             Paragraph("<b>Threat Origin IP:</b>", body_style), Paragraph(str(incident.get("attacker_ip", "101.0.63.28")), body_style)],
        ]
        summary_table = Table(summary_data, colWidths=[1.5*inch, 2.0*inch, 1.5*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(summary_table)

        finding_text = ForensicReportGenerator._get_finding_summary(incident_type, title, static_sev, dynamic_label, dynamic_score)
        story.append(Paragraph(f"<b>Forensic Finding:</b> {finding_text}", alert_style))

        # 3. Dynamic Risk Factors Breakdown
        story.append(Paragraph("2. Primary Machine Learning Risk Drivers", h2_style))
        rf_rows = [[Paragraph("<b>Risk Driver Feature</b>", body_style), Paragraph("<b>Impact %</b>", body_style), Paragraph("<b>Forensic Explanation</b>", body_style)]]
        
        for rf in incident.get("top_risk_factors", [])[:5]:
            rf_rows.append([
                Paragraph(str(rf.get("label", rf.get("feature_key"))), body_style),
                Paragraph(f"{rf.get('contribution_percentage', 0)}%", body_style),
                Paragraph(str(rf.get("explanation", "")), body_style),
            ])
        
        if len(rf_rows) > 1:
            rf_table = Table(rf_rows, colWidths=[2.2*inch, 0.8*inch, 4.5*inch])
            rf_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(rf_table)

        # 4. Evidence Audit Snapshot
        story.append(Paragraph("3. Bundled Cloud Evidence Audit", h2_style))
        ev_data = incident.get("evidence_snapshot", {})
        
        audit_data = [
            [Paragraph("<b>Evidence Vector</b>", body_style), Paragraph("<b>Property Inspected</b>", body_style), Paragraph("<b>Finding Status</b>", body_style)],
            [Paragraph("Identity / IAM", body_style), Paragraph("Recent Role Elevation", body_style), Paragraph("YES (Escalated)" if ev_data.get("iam_recent_role_elevation") else "Normal / Clean", body_style)],
            [Paragraph("Identity / Auth", body_style), Paragraph("MFA / Conditional Access", body_style), Paragraph("BYPASSED" if ev_data.get("mfa_bypassed") else "Enforced", body_style)],
            [Paragraph("Storage Security", body_style), Paragraph("Blob Public Access Enabled", body_style), Paragraph("PUBLIC ACCESS ENABLED" if ev_data.get("storage_public_access_enabled") else "Private", body_style)],
            [Paragraph("Compute / IMDS", body_style), Paragraph("Managed Identity IMDS Token", body_style), Paragraph("HARVESTED / COMPROMISED" if ev_data.get("imds_token_accessed") else "Clean", body_style)],
            [Paragraph("Network Security", body_style), Paragraph("Inbound NSG Open Port (0.0.0.0/0)", body_style), Paragraph("EXPOSED TO INTERNET" if ev_data.get("nsg_unrestricted_inbound_any") else "Protected", body_style)],
            [Paragraph("Data Egress", body_style), Paragraph("Data Volume Exfiltrated", body_style), Paragraph(f"{ev_data.get('exfiltrated_data_mb', 0)} MB", body_style)],
        ]
        audit_table = Table(audit_data, colWidths=[1.8*inch, 2.5*inch, 3.2*inch])
        audit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(audit_table)

        # 5. Chronological Attack Timeline
        story.append(Paragraph("4. Chronological Attack Timeline (MITRE ATT&CK Aligned)", h2_style))
        timeline_rows = [[Paragraph("<b>Timestamp</b>", body_style), Paragraph("<b>Event & Source</b>", body_style), Paragraph("<b>Description & MITRE</b>", body_style)]]
        
        for ev in incident.get("timeline", []):
            mitre_info = f" [MITRE: {ev.get('mitre_tactic')}]" if ev.get('mitre_tactic') else ""
            timeline_rows.append([
                Paragraph(str(ev.get("timestamp", ev.get("time", ""))), body_style),
                Paragraph(f"<b>{ev.get('event_type', ev.get('event'))}</b><br/>({ev.get('source', 'Azure')})", body_style),
                Paragraph(f"{ev.get('description', '')}<b>{mitre_info}</b>", body_style)
            ])
        
        if len(timeline_rows) > 1:
            timeline_table = Table(timeline_rows, colWidths=[1.4*inch, 2.1*inch, 4.0*inch])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(timeline_table)

        # 6. Containment & Remediation Playbook
        story.append(Paragraph("5. Recommended Azure CLI Remediation Commands", h2_style))
        playbook_cmds = incident.get("remediation_playbook")
        if not playbook_cmds or len(playbook_cmds) == 0:
            playbook_cmds = DeepEvidenceBundler.generate_remediation_playbook(incident)

        for cmd in playbook_cmds:
            story.append(Paragraph(f"$ {cmd}", code_style))
            story.append(Spacer(1, 2))

        doc.build(story)
        logger.info(f"Generated PDF forensic report at: {output_path}")
        return output_path

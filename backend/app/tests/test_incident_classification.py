"""
Test Suite for Incident-Type Awareness, Classification, Timeline Construction, and DFIR Reporting.
"""

import os
import sys
from fastapi.testclient import TestClient

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app
from app.services.azure_sentinel import determine_incident_type, AzureSentinelService
from app.services.timeline_builder import TimelineBuilder
from app.services.evidence_bundler import DeepEvidenceBundler
from app.services.report_generator import ForensicReportGenerator


def test_incident_type_classification():
    """Verify that determine_incident_type correctly classifies different attack patterns."""
    
    # 1. Entra ID Brute Force Payload
    entra_payload = {
        "Title": "Entra ID - Brute Force / Account Lockout Detection",
        "AnalyticsRuleName": "Entra ID - Brute Force / Account Lockout Detection",
        "Description": "Repeated failed Microsoft Entra ID authentication attempts resulting in account lockout.",
        "ExtendedProperties": {
            "ResultType": "50053",
            "UserPrincipalName": "test123@corp.onmicrosoft.com",
            "ClientIP": "101.0.63.28",
            "FailureReason": "Account is locked"
        }
    }
    assert determine_incident_type(entra_payload) == "BRUTE_FORCE"

    # 2. IAM Privilege Escalation Payload
    iam_payload = {
        "Title": "Privilege Escalation via Custom Role Assignment",
        "Description": "Identity was granted elevated Contributor role with wildcard permissions.",
        "ExtendedProperties": {"Role": "Owner"}
    }
    assert determine_incident_type(iam_payload) == "PRIVILEGE_ESCALATION"

    # 3. IMDS Token Theft Payload
    imds_payload = {
        "Title": "Suspicious IMDS 169.254.169.254 Probing",
        "Description": "VM instance metadata service queried for system-assigned managed identity token."
    }
    assert determine_incident_type(imds_payload) == "IMDS_TOKEN_THEFT"

    # 4. Storage Blob Exfiltration Payload
    storage_payload = {
        "Title": "Storage Account Public Access & Blob Exfiltration",
        "Description": "High outbound data egress from storage blob container."
    }
    assert determine_incident_type(storage_payload) == "STORAGE_EXPOSURE"

    # 5. Network Scanning Payload
    net_payload = {
        "Title": "Unauthorized Perimeter Port Sweep",
        "Description": "Inbound TCP handshake probe targeting open NSG rules."
    }
    assert determine_incident_type(net_payload) == "NETWORK_ATTACK"

    print("✅ determine_incident_type passed all classification test cases")


def test_sentinel_webhook_ingestion_and_timeline():
    """Verify end-to-end ingestion of Sentinel brute force alert via API."""
    with TestClient(app) as client:
        webhook_payload = {
            "IncidentId": "INC-AZURE-TESTBF01",
            "Title": "Entra ID - Brute Force / Account Lockout Detection",
            "Severity": "Medium",
            "Status": "Active",
            "Entities": [
                {"Kind": "Account", "Name": "test123@corp.onmicrosoft.com"},
                {"Kind": "Ip", "Address": "101.0.63.28"}
            ],
            "ExtendedProperties": {
                "ResultType": "50053",
                "UserPrincipalName": "test123@corp.onmicrosoft.com",
                "ClientIP": "101.0.63.28"
            }
        }

        res = client.post("/api/sentinel/webhook", json=webhook_payload)
        assert res.status_code == 200
        data = res.json()

        assert data["incident_id"] == "INC-AZURE-TESTBF01"
        assert data["title"] == "Entra ID - Brute Force / Account Lockout Detection"
        assert data["incident_type"] == "BRUTE_FORCE"
        assert data["affected_user"] == "test123@corp.onmicrosoft.com"
        assert data["attacker_ip"] == "101.0.63.28"
        assert data["sentinel_static_severity"] == "Medium"

        # Check Timeline
        timeline = data["timeline"]
        assert len(timeline) >= 5
        event_types = [ev["event_type"] for ev in timeline]
        assert "Failed Authentication Attempts" in event_types
        assert "Account Smart Lockout Engaged" in event_types

        # Verify no irrelevant IMDS or port sweep events leaked into Brute Force timeline
        assert not any("IMDS" in ev["event_type"] for ev in timeline)
        assert not any("Port sweep" in ev["description"] for ev in timeline)

        # Check MITRE tactics
        mitre_tactics = [ev.get("mitre_tactic", "") for ev in timeline]
        assert any("T1110" in m for m in mitre_tactics)

        # Check Remediation Playbook
        playbook = data["remediation_playbook"]
        assert len(playbook) > 0
        assert any("test123@corp.onmicrosoft.com" in p for p in playbook)
        assert any("101.0.63.28" in p for p in playbook)

        # Clean up
        client.delete("/api/incidents/INC-AZURE-TESTBF01")
        print("✅ End-to-end Sentinel Brute Force ingestion and timeline verified")


def test_report_generation():
    """Verify Markdown, HTML, and PDF report generation for Brute Force incident."""
    with TestClient(app) as client:
        # Create incident
        inc_payload = {
            "incident_id": "INC-TEST-REPORT",
            "title": "Entra ID - Brute Force / Account Lockout Detection",
            "incident_type": "BRUTE_FORCE",
            "sentinel_static_severity": "Medium",
            "target_resource": "Microsoft Entra ID (Tenant Directory)",
            "affected_user": "test123@corp.onmicrosoft.com",
            "attacker_ip": "101.0.63.28"
        }
        client.post("/api/incidents", json=inc_payload)

        # Markdown Report
        md_res = client.get("/api/incidents/INC-TEST-REPORT/report?format=markdown")
        assert md_res.status_code == 200
        assert "BRUTE_FORCE" in md_res.text
        assert "T1110" in md_res.text

        # HTML Report
        html_res = client.get("/api/incidents/INC-TEST-REPORT/report?format=html")
        assert html_res.status_code == 200
        assert "Entra ID - Brute Force / Account Lockout Detection" in html_res.text

        # PDF Report
        pdf_res = client.get("/api/incidents/INC-TEST-REPORT/report?format=pdf")
        assert pdf_res.status_code == 200
        assert len(pdf_res.content) > 1000

        # Clean up
        client.delete("/api/incidents/INC-TEST-REPORT")
        print("✅ Forensic report generation (MD, HTML, PDF) for Brute Force verified")


def test_logic_app_sentinel_schema():
    """Verify that incoming payload from Azure Logic App / Automation Rule is correctly parsed."""
    with TestClient(app) as client:
        logic_app_payload = {
            "SchemaType": "Incident",
            "objectEventType": "Create",
            "workspaceInfo": {
                "SubscriptionId": "0e3bb114-e13e-4c03-9357-7aa7a1068480",
                "ResourceGroupName": "forensic-demo-rg",
                "WorkspaceName": "forensic-law-workspace"
            },
            "object": {
                "id": "11d0db09-44b0-4a65-98d3-4e2df2427fd7",
                "name": "11d0db09-44b0-4a65-98d3-4e2df2427fd7",
                "properties": {
                    "title": "Entra ID - Brute Force / Account Lockout Detection",
                    "description": "Detects failed Microsoft Entra ID sign-in activity that may indicate password brute-force or repeated authentication attempts.",
                    "severity": "Medium",
                    "status": "New",
                    "incidentNumber": 1,
                    "additionalData": {
                        "tactics": ["CredentialAccess"],
                        "techniques": ["T1110"]
                    },
                    "alerts": [
                        {
                            "properties": {
                                "alertDisplayName": "Entra ID - Brute Force / Account Lockout Detection",
                                "additionalData": {
                                    "Analytic Rule Name": "Entra ID - Brute Force / Account Lockout Detection"
                                }
                            }
                        }
                    ]
                }
            }
        }

        res = client.post("/api/sentinel/webhook", json=logic_app_payload)
        assert res.status_code == 200
        data = res.json()

        assert data["title"] == "Entra ID - Brute Force / Account Lockout Detection"
        assert data["incident_type"] == "BRUTE_FORCE"
        assert len(data["timeline"]) >= 5
        client.delete(f"/api/incidents/{data['incident_id']}")
        print("✅ Logic App Sentinel schema ingestion verified")


if __name__ == "__main__":
    test_incident_type_classification()
    test_sentinel_webhook_ingestion_and_timeline()
    test_logic_app_sentinel_schema()
    test_report_generation()
    print("\n🎉 ALL INCIDENT-TYPE AWARENESS & CLASSIFICATION TESTS PASSED! 🎉\n")

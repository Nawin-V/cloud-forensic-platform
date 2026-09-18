"""
End-to-End Test for ML Dynamic Severity Engine and Forensic Report Generator.
"""

import os
import sys
import tempfile
import pytest

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.ml.model_trainer import train, load_dataset
from app.ml.predictor import DynamicSeverityPredictor
from app.services.report_generator import ForensicReportGenerator


def test_dataset_loading():
    """Verify the 600-sample training dataset loads with all required features."""
    X, y = load_dataset()
    assert len(X) == 600, f"Expected 600 samples, got {len(X)}"
    assert len(y) == 600
    assert X.shape[1] == 13, f"Expected 13 feature columns, got {X.shape[1]}"
    print("✅ Dataset loading test passed (600 samples, 13 features)")


def test_model_training_metrics():
    """Verify model training produces high R2 score (> 0.85) on cross-validation."""
    metrics = train()
    assert "metrics" in metrics
    r2_score = metrics["metrics"]["r2_score"]
    cv_r2 = metrics["metrics"]["cv_r2_score"]
    print(f"\n[ML Eval] Test R2: {r2_score:.4f}, CV R2: {cv_r2:.4f}, Best Algo: {metrics['best_algorithm']}")
    assert r2_score > 0.85, f"R2 score too low: {r2_score}"
    assert cv_r2 > 0.80, f"CV R2 score too low: {cv_r2}"
    assert len(metrics["top_features"]) == 13
    print("✅ Model training test passed")


def test_predictor_inference():
    """Verify dynamic scoring inference and explainability on realistic attack scenarios."""
    predictor = DynamicSeverityPredictor.get_instance()

    # Scenario 1: Critical Compromise (Sentinel marked Low, but deep evidence shows high risk)
    critical_evidence = {
        "incident_id": "INC-TEST-001",
        "sentinel_static_severity_code": 1,  # Sentinel says "Low"
        "iam_recent_role_elevation": 1,
        "iam_scope_level_code": 2,
        "mfa_bypassed": 1,
        "unusual_geo_ip": 1,
        "storage_public_access_enabled": 1,
        "storage_sas_unrestricted": 1,
        "exfiltrated_data_mb": 904.0,
        "nsg_unrestricted_inbound_any": 1,
        "imds_token_accessed": 1,
        "keyvault_secret_accessed": 1,
        "contains_sensitive_pii_flag": 1,
        "custom_role_wildcard_perm": 1
    }

    result = predictor.predict(critical_evidence)
    print(f"\n[Inference Critical] Dynamic Score: {result['dynamic_ml_risk_score']} ({result['dynamic_risk_label']})")
    print(f"[Inference Critical] Static Severity: {result['static_severity']}, Delta: {result['severity_delta']}")
    
    assert result["dynamic_ml_risk_score"] >= 80.0, f"Expected Critical score >= 80, got {result['dynamic_ml_risk_score']}"
    assert result["dynamic_risk_label"] in ["High", "Critical"]
    assert result["is_escalated"] is True
    assert len(result["top_risk_factors"]) > 0

    # Scenario 2: Low Risk / False Alarm
    low_evidence = {
        "incident_id": "INC-TEST-002",
        "sentinel_static_severity_code": 1,
        "iam_recent_role_elevation": 0,
        "iam_scope_level_code": 0,
        "mfa_bypassed": 0,
        "unusual_geo_ip": 0,
        "storage_public_access_enabled": 0,
        "storage_sas_unrestricted": 0,
        "exfiltrated_data_mb": 12.0,
        "nsg_unrestricted_inbound_any": 0,
        "imds_token_accessed": 0,
        "keyvault_secret_accessed": 0,
        "contains_sensitive_pii_flag": 0,
        "custom_role_wildcard_perm": 0
    }
    low_result = predictor.predict(low_evidence)
    print(f"[Inference Low] Dynamic Score: {low_result['dynamic_ml_risk_score']} ({low_result['dynamic_risk_label']})")
    assert low_result["dynamic_ml_risk_score"] < 40.0, f"Expected Low score < 40, got {low_result['dynamic_ml_risk_score']}"
    assert low_result["dynamic_risk_label"] == "Low"
    print("✅ Predictor inference tests passed")


def test_forensic_report_generation(output_dir=None):
    """Verify Markdown, HTML, and PDF forensic report generation."""
    predictor = DynamicSeverityPredictor.get_instance()

    test_incident = {
        "incident_id": "INC-SIM-1011",
        "title": "Suspected IMDS Token Exfiltration & IAM Privilege Escalation",
        "sentinel_static_severity": "Low",
        "target_resource": "/subscriptions/sub-123/resourceGroups/ProdRG/providers/Microsoft.Compute/virtualMachines/vm-prod-app-01",
        "affected_user": "app-admin@corp.azure.com",
        "attacker_ip": "185.220.101.5 (TOR Exit Node)",
        "created_at": "2026-09-02T08:15:30Z",
        "timeline": [
            {"timestamp": "08:12:00", "event_type": "Brute Force Sign-in", "source": "AAD Identity Protection", "description": "Failed logins from untrusted IP", "mitre_tactic": "T1110"},
            {"timestamp": "08:15:30", "event_type": "Sentinel Alert Triggered", "source": "Azure Sentinel", "description": "Alert: Anomalous login detected (Static: Low)", "mitre_tactic": "T1078"},
            {"timestamp": "08:16:10", "event_type": "IMDS Credential Harvest", "source": "Host Forensics", "description": "Curled 169.254.169.254 for Managed Identity token", "mitre_tactic": "T1552.005"},
            {"timestamp": "08:18:45", "event_type": "IAM Role Escalation", "source": "Azure Activity Log", "description": "Assigned Contributor role at Subscription scope", "mitre_tactic": "T1098"}
        ],
        "evidence_snapshot": {
            "iam_recent_role_elevation": 1,
            "iam_scope_level_code": 2,
            "mfa_bypassed": 1,
            "unusual_geo_ip": 1,
            "storage_public_access_enabled": 1,
            "storage_sas_unrestricted": 1,
            "exfiltrated_data_mb": 512.4,
            "nsg_unrestricted_inbound_any": 1,
            "imds_token_accessed": 1,
            "keyvault_secret_accessed": 1,
            "contains_sensitive_pii_flag": 1,
            "custom_role_wildcard_perm": 0
        }
    }

    # Run prediction to enrich
    pred_res = predictor.predict(test_incident["evidence_snapshot"])
    test_incident.update(pred_res)

    # 1. Test Markdown
    md_report = ForensicReportGenerator.generate_markdown(test_incident)
    assert "# 🔒 Cloud Security Forensic Investigation Report" in md_report
    assert "INC-SIM-1011" in md_report
    print("✅ Markdown report generated successfully")

    # 2. Test HTML
    html_report = ForensicReportGenerator.generate_html(test_incident)
    assert "<!DOCTYPE html>" in html_report
    assert "INC-SIM-1011" in html_report
    print("✅ HTML report generated successfully")

    # 3. Test PDF
    target_dir = output_dir or tempfile.gettempdir()
    pdf_path = os.path.join(target_dir, "test_report.pdf")
    generated_path = ForensicReportGenerator.generate_pdf(test_incident, pdf_path)
    assert os.path.exists(generated_path)
    assert os.path.getsize(generated_path) > 1000  # Valid non-empty PDF binary
    print(f"✅ PDF report generated successfully ({os.path.getsize(generated_path)} bytes at {pdf_path})")


if __name__ == "__main__":
    test_dataset_loading()
    test_model_training_metrics()
    test_predictor_inference()
    test_forensic_report_generation()
    print("\n🎉 ALL UNIT & INTEGRATION TESTS PASSED SUCCESSFULLY! 🎉\n")

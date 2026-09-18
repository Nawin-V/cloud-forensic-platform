"""
Integration Test for FastAPI Endpoints.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app


def test_api_suite():
    with TestClient(app) as client:
        # 1. Health
        health_res = client.get("/health")
        assert health_res.status_code == 200
        assert health_res.json()["status"] == "healthy"
        print("✅ /health endpoint passed")

        # 2. Storage Status
        storage_res = client.get("/api/storage/status")
        assert storage_res.status_code == 200
        print(f"✅ /api/storage/status passed (Storage Mode: {storage_res.json()['storage_mode']})")

        # 3. ML Metrics
        ml_res = client.get("/api/ml/metrics")
        assert ml_res.status_code == 200
        ml_data = ml_res.json()
        assert "metrics" in ml_data
        assert "top_features" in ml_data
        print(f"✅ /api/ml/metrics passed (Algorithm: {ml_data.get('best_algorithm')}, R2: {ml_data['metrics']['r2_score']:.4f})")

        # 4. List Incidents
        inc_res = client.get("/api/incidents")
        assert inc_res.status_code == 200
        print(f"✅ /api/incidents passed ({len(inc_res.json())} active incidents retrieved)")

        # 5. Create Test Incident dynamically
        test_payload = {
            "incident_id": "INC-TEST-UNIT",
            "title": "Unit Test Simulated Exfiltration Scenario",
            "sentinel_static_severity": "Low",
            "status": "Investigating",
            "target_resource": "/subscriptions/sub-unit-test/resourceGroups/Test-RG/providers/Microsoft.Storage/storageAccounts/testsa",
            "affected_user": "test-analyst@corp.local",
            "attacker_ip": "194.26.29.112",
            "evidence_snapshot": {
                "sentinel_static_severity_code": 1,
                "storage_public_access_enabled": 0,
                "role_assignment_elevated": 0,
                "exfiltrated_data_mb": 50.0
            }
        }
        create_res = client.post("/api/incidents", json=test_payload)
        assert create_res.status_code == 200
        print("✅ /api/incidents POST passed")

        # 6. Incident Detail & Rescore
        detail_res = client.get("/api/incidents/INC-TEST-UNIT")
        assert detail_res.status_code == 200
        inc = detail_res.json()
        assert inc["incident_id"] == "INC-TEST-UNIT"
        assert "dynamic_ml_risk_score" in inc
        print(f"✅ /api/incidents/INC-TEST-UNIT passed (Score: {inc['dynamic_ml_risk_score']}, Label: {inc['dynamic_risk_label']})")

        # 7. Test Rescoring Endpoint
        rescore_res = client.post("/api/incidents/INC-TEST-UNIT/rescore", json={
            "storage_public_access_enabled": 1,
            "role_assignment_elevated": 1,
            "sentinel_static_severity_code": 3,
            "exfiltrated_data_mb": 950.0,
            "cross_region_activity_detected": 1
        })
        assert rescore_res.status_code == 200
        updated_inc = rescore_res.json()
        assert updated_inc["dynamic_ml_risk_score"] > inc["dynamic_ml_risk_score"]
        print(f"✅ /api/incidents/INC-TEST-UNIT/rescore passed (Updated Score: {updated_inc['dynamic_ml_risk_score']})")


        # 8. Test Forensic Report Exports (Markdown, HTML, PDF)
        md_res = client.get("/api/incidents/INC-TEST-UNIT/report?format=markdown")
        assert md_res.status_code == 200
        assert "Cloud Security Forensic Investigation Report" in md_res.text
        print("✅ /api/incidents/INC-TEST-UNIT/report?format=markdown passed")

        html_res = client.get("/api/incidents/INC-TEST-UNIT/report?format=html")
        assert html_res.status_code == 200
        assert "<!DOCTYPE html>" in html_res.text
        print("✅ /api/incidents/INC-TEST-UNIT/report?format=html passed")

        pdf_res = client.get("/api/incidents/INC-TEST-UNIT/report?format=pdf")
        assert pdf_res.status_code == 200
        assert len(pdf_res.content) > 1000
        print(f"✅ /api/incidents/INC-TEST-UNIT/report?format=pdf passed ({len(pdf_res.content)} bytes)")

        # 9. Clean up test incident to leave storage completely clean
        del_res = client.delete("/api/incidents/INC-TEST-UNIT")
        assert del_res.status_code == 200
        print("✅ /api/incidents/INC-TEST-UNIT DELETE passed (Storage clean)")




if __name__ == "__main__":
    test_api_suite()
    print("\n🎉 ALL FASTAPI API ENDPOINT & REPORTING TESTS PASSED! 🎉\n")

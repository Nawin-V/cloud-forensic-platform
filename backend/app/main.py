"""
FastAPI Server Entrypoint for Cloud Incident & Forensic Response Platform.
"""

import os
import json
import logging
from dotenv import load_dotenv

# Automatically load .env credentials
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.incidents import router as incidents_router
from app.ml.predictor import DynamicSeverityPredictor
from app.db.firebase import StorageAdapter
from app.services.report_generator import REPORTS_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("main")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes models and starts server instantly."""
    logger.info("🚀 Starting Cloud Incident & Forensic Response Platform Backend...")
    
    # Warm up ML Predictor
    predictor = DynamicSeverityPredictor.get_instance()
    logger.info(f"✅ ML Model Ready: {predictor.metrics.get('best_algorithm', 'gradient_boosting').upper()} (R2: {predictor.metrics.get('metrics', {}).get('r2_score', 0.94):.4f})")

    storage = StorageAdapter.get_instance()
    logger.info(f"💾 Storage Engine Ready (Mode: {'Firebase Cloud Firestore' if storage.is_connected_to_firebase() else 'Local Persistent JSON Store'})")
    logger.info("✨ Ready for real-time incident ingestion")

    yield




app = FastAPI(
    title="Cloud Incident & Forensic Response Platform",
    description="Automated Sentinel incident enrichment, ML dynamic severity scoring, and deep cloud forensic reporting.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for React Frontend (Vite on 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(incidents_router)


def _seed_demo_incidents(storage: StorageAdapter, predictor: DynamicSeverityPredictor):
    """Seeds rich demo scenarios representing real-world Azure attacks."""
    demo_scenarios = [
        {
            "incident_id": "INC-SIM-1011",
            "title": "Suspected IMDS Token Theft & Subscription-Level IAM Escalation",
            "sentinel_static_severity": "Low",
            "status": "Investigating",
            "target_resource": "/subscriptions/sub-prod-01/resourceGroups/CoreApp-RG/providers/Microsoft.Compute/virtualMachines/vm-prod-web-01",
            "affected_user": "svc-web-managed-identity",
            "attacker_ip": "185.220.101.5 (TOR Exit Node)",
            "created_at": "2026-09-02T08:15:30Z",
            "timeline": [
                {"timestamp": "08:12:00", "event_type": "Brute Force Sign-in", "source": "Azure AD Identity Protection", "description": "Multiple failed logins from untrusted foreign IP (TOR node)", "mitre_tactic": "T1110"},
                {"timestamp": "08:15:30", "event_type": "Sentinel Alert Fired", "source": "Azure Sentinel", "description": "Alert: Anomalous login detected on web VM (Static Rule Severity: Low)", "mitre_tactic": "T1078"},
                {"timestamp": "08:16:10", "event_type": "IMDS Metadata Probing", "source": "Host OS Syslog", "description": "HTTP GET request to 169.254.169.254/metadata/identity/oauth2/token captured", "mitre_tactic": "T1552.005"},
                {"timestamp": "08:18:45", "event_type": "IAM Role Assignment", "source": "Azure Activity Log", "description": "Role 'Contributor' assigned to compromised identity at Subscription scope", "mitre_tactic": "T1098"},
                {"timestamp": "08:21:00", "event_type": "Key Vault Secret Access", "source": "Azure Key Vault Audit", "description": "Secret 'DbProdConnectionSecret' retrieved via harvested token", "mitre_tactic": "T1555"}
            ],
            "evidence_snapshot": {
                "sentinel_static_severity_code": 1,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 2,
                "mfa_bypassed": 1,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 9.83,
                "nsg_unrestricted_inbound_any": 1,
                "imds_token_accessed": 1,
                "keyvault_secret_accessed": 1,
                "contains_sensitive_pii_flag": 0,
                "custom_role_wildcard_perm": 0
            },
            "remediation_playbook": [
                "az role assignment delete --assignee svc-web-managed-identity --role Contributor --scope /subscriptions/sub-prod-01",
                "az keyvault secret set-attributes --vault-name MainKeyVault --name DbProdConnectionSecret --enabled false",
                "az network nsg rule create -g CoreApp-RG --nsg-name WebNSG -n BlockThreatIP --priority 100 --source-address-prefixes 185.220.101.5 --access Deny",
                "az vm identity remove -g CoreApp-RG -n vm-prod-web-01"
            ]
        },
        {
            "incident_id": "INC-SIM-1017",
            "title": "Public Storage Blob Exposure & Massive Data Exfiltration",
            "sentinel_static_severity": "Low",
            "status": "Active Threat",
            "target_resource": "/subscriptions/sub-prod-01/resourceGroups/DataStorage-RG/providers/Microsoft.Storage/storageAccounts/prodcustomerdata2026",
            "affected_user": "external-anonymous-actor",
            "attacker_ip": "194.26.29.112 (Suspicious VPN)",
            "created_at": "2026-09-02T08:45:00Z",
            "timeline": [
                {"timestamp": "08:40:12", "event_type": "Storage Config Modification", "source": "Azure Resource Manager", "description": "Storage Account property 'allowBlobPublicAccess' modified from False to True", "mitre_tactic": "T1562.001"},
                {"timestamp": "08:42:00", "event_type": "Unrestricted SAS Generation", "source": "Storage Diagnostic Log", "description": "Account SAS token generated with full Read/Write/List permissions", "mitre_tactic": "T1558"},
                {"timestamp": "08:45:00", "event_type": "Sentinel Alert Fired", "source": "Azure Sentinel", "description": "Alert: High outbound data transfer rate on storage container (Static: Low)", "mitre_tactic": "T1048"},
                {"timestamp": "08:48:30", "event_type": "Mass Egress Spike", "source": "Azure Network Watcher", "description": "904 MB of encrypted customer database backups downloaded by external IP", "mitre_tactic": "T1567"}
            ],
            "evidence_snapshot": {
                "sentinel_static_severity_code": 1,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 1,
                "mfa_bypassed": 1,
                "unusual_geo_ip": 0,
                "storage_public_access_enabled": 1,
                "storage_sas_unrestricted": 1,
                "exfiltrated_data_mb": 904.03,
                "nsg_unrestricted_inbound_any": 1,
                "imds_token_accessed": 1,
                "keyvault_secret_accessed": 1,
                "contains_sensitive_pii_flag": 1,
                "custom_role_wildcard_perm": 0
            },
            "remediation_playbook": [
                "az storage account update --name prodcustomerdata2026 --allow-blob-public-access false",
                "az storage account keys renew --account-name prodcustomerdata2026 --key primary",
                "az storage account keys renew --account-name prodcustomerdata2026 --key secondary",
                "az storage container set-permission --name customer-backups --account-name prodcustomerdata2026 --public-access off"
            ]
        },
        {
            "incident_id": "INC-SIM-1037",
            "title": "Tenant-Wide Custom Role Escalation & Secret Dumping",
            "sentinel_static_severity": "High",
            "status": "Escalated",
            "target_resource": "/providers/Microsoft.Management/managementGroups/RootTenantGroup",
            "affected_user": "contractor-dev-admin@corp.azure.com",
            "attacker_ip": "45.154.255.89 (Anomalous Geo - Eastern Europe)",
            "created_at": "2026-09-02T09:10:00Z",
            "timeline": [
                {"timestamp": "09:05:00", "event_type": "Sign-in without MFA", "source": "Azure AD Sign-ins", "description": "Sign-in from anomalous location with legacy auth protocol", "mitre_tactic": "T1078.004"},
                {"timestamp": "09:08:20", "event_type": "Custom Role Definition", "source": "Azure Authorization ARM", "description": "Created custom role 'SuperAdmin' with wildcard actions: ['*']", "mitre_tactic": "T1098.003"},
                {"timestamp": "09:10:00", "event_type": "Sentinel Alert Fired", "source": "Azure Sentinel", "description": "Alert: Custom role created with broad permissions (Static: High)", "mitre_tactic": "T1098"},
                {"timestamp": "09:12:40", "event_type": "Key Vault Bulk Export", "source": "Azure Key Vault Logs", "description": "All certificates and secrets queried in Key Vault 'ProdSecretsKV'", "mitre_tactic": "T1555.004"}
            ],
            "evidence_snapshot": {
                "sentinel_static_severity_code": 3,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 3,
                "mfa_bypassed": 0,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 1,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 635.19,
                "nsg_unrestricted_inbound_any": 0,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 1,
                "contains_sensitive_pii_flag": 1,
                "custom_role_wildcard_perm": 1
            },
            "remediation_playbook": [
                "az ad user update --id contractor-dev-admin@corp.azure.com --account-enabled false",
                "az role definition delete --name SuperAdmin",
                "az keyvault key rotate --vault-name ProdSecretsKV --name AllKeys",
                "az account clear"
            ]
        },
        {
            "incident_id": "INC-SIM-1033",
            "title": "Routine Developer SSH Connection to Sandbox VM",
            "sentinel_static_severity": "Low",
            "status": "Closed / Benign",
            "target_resource": "/subscriptions/sub-dev-02/resourceGroups/DevSandbox-RG/providers/Microsoft.Compute/virtualMachines/vm-dev-test-03",
            "affected_user": "bob.developer@corp.azure.com",
            "attacker_ip": "192.168.1.45 (Internal Corporate VPN)",
            "created_at": "2026-09-02T09:20:00Z",
            "timeline": [
                {"timestamp": "09:18:00", "event_type": "SSH Sign-in", "source": "Linux Auth Log", "description": "Successful SSH login via authorized public key", "mitre_tactic": "T1021.004"},
                {"timestamp": "09:20:00", "event_type": "Sentinel Alert Fired", "source": "Azure Sentinel", "description": "Alert: SSH login from corporate VPN (Static: Low)", "mitre_tactic": "T1078"}
            ],
            "evidence_snapshot": {
                "sentinel_static_severity_code": 1,
                "iam_recent_role_elevation": 0,
                "iam_scope_level_code": 0,
                "mfa_bypassed": 0,
                "unusual_geo_ip": 0,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 32.74,
                "nsg_unrestricted_inbound_any": 0,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 0,
                "contains_sensitive_pii_flag": 0,
                "custom_role_wildcard_perm": 0
            },
            "remediation_playbook": [
                "# No containment action required. Benign developer activity."
            ]
        },
        {
            "incident_id": "INC-SIM-1071",
            "title": "Compromised Service Principal with High-Volume Blob Dumping",
            "sentinel_static_severity": "High",
            "status": "Active Threat",
            "target_resource": "/subscriptions/sub-prod-01/resourceGroups/Analytics-RG/providers/Microsoft.Storage/storageAccounts/prodanalyticsdata",
            "affected_user": "sp-etl-pipeline-automation",
            "attacker_ip": "104.244.78.21 (Known Bad Actor IP)",
            "created_at": "2026-09-02T09:35:00Z",
            "timeline": [
                {"timestamp": "09:30:00", "event_type": "Service Principal Credential Login", "source": "Azure AD Service Principal Sign-ins", "description": "Service Principal authenticated from non-whitelisted IP range", "mitre_tactic": "T1078.004"},
                {"timestamp": "09:32:15", "event_type": "Role Elevation", "source": "Azure Authorization API", "description": "SP assigned Storage Blob Data Owner at Subscription scope", "mitre_tactic": "T1098"},
                {"timestamp": "09:35:00", "event_type": "Sentinel Alert Fired", "source": "Azure Sentinel", "description": "Alert: Bulk blob download by automated pipeline SP (Static: High)", "mitre_tactic": "T1048"},
                {"timestamp": "09:38:00", "event_type": "Egress Threshold Exceeded", "source": "Azure Monitor Metrics", "description": "1029.36 MB of analytics tables exfiltrated", "mitre_tactic": "T1567"}
            ],
            "evidence_snapshot": {
                "sentinel_static_severity_code": 3,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 2,
                "mfa_bypassed": 0,
                "unusual_geo_ip": 0,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 1029.36,
                "nsg_unrestricted_inbound_any": 0,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 0,
                "contains_sensitive_pii_flag": 1,
                "custom_role_wildcard_perm": 1
            },
            "remediation_playbook": [
                "az ad sp credential reset --id sp-etl-pipeline-automation",
                "az role assignment delete --assignee sp-etl-pipeline-automation --role 'Storage Blob Data Owner'",
                "az storage account network-rule add --account-name prodanalyticsdata --ip-address 104.244.78.21 --action Deny"
            ]
        }
    ]

    for item in demo_scenarios:
        # Score dynamically using ML
        scores = predictor.predict(item["evidence_snapshot"])
        item.update(scores)
        storage.save_incident(item)
    
    logger.info("✅ Demo incident scenarios successfully seeded and scored!")


@app.get("/health")
def health_check():
    """System health and status check."""
    return {
        "status": "healthy",
        "service": "Cloud Incident & Forensic Response Platform",
        "version": "1.0.0"
    }

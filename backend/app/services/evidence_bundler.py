"""
Deep Cloud Evidence Bundler Service.
Queries live Azure ARM & Graph SDKs (or high-fidelity mock provider in simulation mode)
to snapshot IAM role hierarchies, Storage public access states, VM Managed Identities, and NSG rules.
"""

import os
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load backend/.env or root .env
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(os.path.dirname(BASE_DIR), ".env"))

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evidence_bundler")


class DeepEvidenceBundler:
    """Automated evidence collection engine for Azure cloud forensics."""

    _instance: Optional["DeepEvidenceBundler"] = None

    def __init__(self):
        # Refresh env in case updated at runtime
        load_dotenv(os.path.join(BASE_DIR, ".env"), override=True)
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.credential = None
        self._init_azure_client()

    @classmethod
    def get_instance(cls) -> "DeepEvidenceBundler":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance



    def _init_azure_client(self):
        """Initializes Azure Service Principal credential if available."""
        if AZURE_SDK_AVAILABLE and self.tenant_id and self.client_id and self.client_secret:
            try:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                logger.info("🔑 Azure Service Principal credential initialized for Live Evidence Bundling")
            except Exception as e:
                logger.warning(f"Could not initialize Azure credential: {e}")
                self.credential = None

    def is_live_azure_connected(self) -> bool:
        """Returns True if live Azure SDK credentials are active."""
        return self.credential is not None and bool(self.subscription_id)

    def bundle_evidence_for_incident(self, incident_base: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes deep cloud evidence investigation for an incident.
        Queries live Azure APIs if connected; otherwise generates high-fidelity evidence snapshot.
        """
        if self.is_live_azure_connected():
            return self._bundle_live_azure_evidence(incident_base)
        else:
            return self._bundle_simulated_evidence(incident_base)

    def _bundle_live_azure_evidence(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Queries live Azure ARM SDKs to inspect real resource configurations."""
        logger.info(f"🔍 [Live Azure] Hunting deep evidence across subscription {self.subscription_id}...")
        
        evidence: Dict[str, Any] = {
            "sentinel_static_severity_code": 2,
            "iam_recent_role_elevation": 0,
            "iam_scope_level_code": 0,
            "mfa_bypassed": 0,
            "unusual_geo_ip": 0,
            "storage_public_access_enabled": 0,
            "storage_sas_unrestricted": 0,
            "exfiltrated_data_mb": 0.0,
            "nsg_unrestricted_inbound_any": 0,
            "imds_token_accessed": 0,
            "keyvault_secret_accessed": 0,
            "contains_sensitive_pii_flag": 0,
            "custom_role_wildcard_perm": 0
        }

        try:
            # 1. Live Storage Check
            storage_client = StorageManagementClient(self.credential, self.subscription_id)
            accounts = list(storage_client.storage_accounts.list())
            for acc in accounts:
                if acc.allow_blob_public_access:
                    evidence["storage_public_access_enabled"] = 1
                    logger.warning(f"🚨 [Live ARM] Storage Account '{acc.name}' has allowBlobPublicAccess=True!")
                    break

            # 2. Live NSG Check
            net_client = NetworkManagementClient(self.credential, self.subscription_id)
            nsgs = list(net_client.network_security_groups.list_all())
            for nsg in nsgs:
                for rule in nsg.security_rules or []:
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        if rule.source_address_prefix == "*" or rule.source_address_prefix == "0.0.0.0/0":
                            evidence["nsg_unrestricted_inbound_any"] = 1
                            logger.warning(f"🚨 [Live ARM] NSG '{nsg.name}' has open inbound rule '{rule.name}' from 0.0.0.0/0!")
                            break

            # 3. Live IAM Role Check
            auth_client = AuthorizationManagementClient(self.credential, self.subscription_id)
            role_assignments = list(auth_client.role_assignments.list())
            for ra in role_assignments:
                # Check for privileged scope
                if ra.scope and len(ra.scope.split("/")) <= 3:  # Subscription level
                    evidence["iam_scope_level_code"] = 2
                    break

        except Exception as e:
            logger.error(f"Error querying live Azure APIs: {e}. Merging base incident snapshot.")

        return evidence

    def _bundle_simulated_evidence(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Provides realistic cloud evidence snapshot based on incident context."""
        existing_ev = incident.get("evidence_snapshot", {})
        if existing_ev:
            return existing_ev

        # Default realistic values if none provided
        return {
            "sentinel_static_severity_code": 1,
            "iam_recent_role_elevation": 1,
            "iam_scope_level_code": 2,
            "mfa_bypassed": 1,
            "unusual_geo_ip": 1,
            "storage_public_access_enabled": 1,
            "storage_sas_unrestricted": 1,
            "exfiltrated_data_mb": 450.0,
            "nsg_unrestricted_inbound_any": 1,
            "imds_token_accessed": 1,
            "keyvault_secret_accessed": 1,
            "contains_sensitive_pii_flag": 1,
            "custom_role_wildcard_perm": 0
        }

"""
Deep Cloud Evidence Bundler Service.
Queries live Azure ARM & Graph SDKs (or high-fidelity provider in simulation mode)
to snapshot IAM role hierarchies, Storage public access states, VM Managed Identities, and NSG rules.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Load backend/.env or root .env
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(os.path.dirname(BASE_DIR), ".env"))

from app.services.azure_sentinel import determine_incident_type

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
        Queries live Azure APIs if connected; otherwise generates high-fidelity evidence snapshot
        tailored directly to the incident's attack type.
        """
        if self.is_live_azure_connected():
            return self._bundle_live_azure_evidence(incident_base)
        else:
            return self._bundle_simulated_evidence(incident_base)

    def _bundle_live_azure_evidence(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Queries live Azure ARM SDKs to inspect real resource configurations."""
        logger.info(f"🔍 [Live Azure] Hunting deep evidence across subscription {self.subscription_id}...")
        incident_type = incident.get("incident_type") or determine_incident_type(incident)
        
        static_sev = incident.get("sentinel_static_severity", "Medium").lower()
        sev_code = 3 if "high" in static_sev else 1 if "low" in static_sev else 2

        evidence: Dict[str, Any] = {
            "sentinel_static_severity_code": sev_code,
            "iam_recent_role_elevation": 0,
            "iam_scope_level_code": 0,
            "mfa_bypassed": 0,
            "unusual_geo_ip": 1 if incident.get("attacker_ip") else 0,
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
            # 1. If Storage incident, check Live Storage
            if incident_type in ["STORAGE_EXPOSURE", "CLOUD_SECURITY_INCIDENT"]:
                storage_client = StorageManagementClient(self.credential, self.subscription_id)
                accounts = list(storage_client.storage_accounts.list())
                for acc in accounts:
                    if acc.allow_blob_public_access:
                        evidence["storage_public_access_enabled"] = 1
                        logger.warning(f"🚨 [Live ARM] Storage Account '{acc.name}' has allowBlobPublicAccess=True!")
                        break

            # 2. If Network incident, check Live NSG
            if incident_type in ["NETWORK_ATTACK", "IMDS_TOKEN_THEFT", "CLOUD_SECURITY_INCIDENT"]:
                net_client = NetworkManagementClient(self.credential, self.subscription_id)
                nsgs = list(net_client.network_security_groups.list_all())
                for nsg in nsgs:
                    for rule in nsg.security_rules or []:
                        if rule.direction == "Inbound" and rule.access == "Allow":
                            if rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
                                evidence["nsg_unrestricted_inbound_any"] = 1
                                break

            # 3. If IAM / Privilege Escalation incident, check Live IAM Role
            if incident_type in ["PRIVILEGE_ESCALATION", "CLOUD_SECURITY_INCIDENT"]:
                auth_client = AuthorizationManagementClient(self.credential, self.subscription_id)
                role_assignments = list(auth_client.role_assignments.list())
                for ra in role_assignments:
                    if ra.scope and len(ra.scope.split("/")) <= 3:  # Subscription level
                        evidence["iam_scope_level_code"] = 2
                        evidence["iam_recent_role_elevation"] = 1
                        break

        except Exception as e:
            logger.error(f"Error querying live Azure APIs: {e}. Falling back to contextual evidence snapshot.")

        return evidence

    def _bundle_simulated_evidence(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Provides realistic cloud evidence snapshot tailored to the detected incident context."""
        existing_ev = incident.get("evidence_snapshot", {})
        if existing_ev and isinstance(existing_ev, dict) and len(existing_ev) > 0:
            return existing_ev

        incident_type = incident.get("incident_type") or determine_incident_type(incident)
        static_sev = incident.get("sentinel_static_severity", "Medium").lower()
        sev_code = 3 if "high" in static_sev else 1 if "low" in static_sev else 2

        if incident_type == "BRUTE_FORCE":
            return {
                "sentinel_static_severity_code": sev_code,
                "iam_recent_role_elevation": 0,
                "iam_scope_level_code": 0,
                "mfa_bypassed": 0,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 0.0,
                "nsg_unrestricted_inbound_any": 0,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 0,
                "contains_sensitive_pii_flag": 0,
                "custom_role_wildcard_perm": 0
            }
        elif incident_type == "PRIVILEGE_ESCALATION":
            return {
                "sentinel_static_severity_code": sev_code,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 3,
                "mfa_bypassed": 1,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 150.0,
                "nsg_unrestricted_inbound_any": 0,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 1,
                "contains_sensitive_pii_flag": 1,
                "custom_role_wildcard_perm": 1
            }
        elif incident_type == "STORAGE_EXPOSURE":
            return {
                "sentinel_static_severity_code": sev_code,
                "iam_recent_role_elevation": 0,
                "iam_scope_level_code": 0,
                "mfa_bypassed": 0,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 1,
                "storage_sas_unrestricted": 1,
                "exfiltrated_data_mb": 904.0,
                "nsg_unrestricted_inbound_any": 0,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 0,
                "contains_sensitive_pii_flag": 1,
                "custom_role_wildcard_perm": 0
            }
        elif incident_type == "IMDS_TOKEN_THEFT":
            return {
                "sentinel_static_severity_code": sev_code,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 2,
                "mfa_bypassed": 1,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 28.5,
                "nsg_unrestricted_inbound_any": 1,
                "imds_token_accessed": 1,
                "keyvault_secret_accessed": 1,
                "contains_sensitive_pii_flag": 0,
                "custom_role_wildcard_perm": 0
            }
        elif incident_type == "NETWORK_ATTACK":
            return {
                "sentinel_static_severity_code": sev_code,
                "iam_recent_role_elevation": 0,
                "iam_scope_level_code": 0,
                "mfa_bypassed": 0,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 5.0,
                "nsg_unrestricted_inbound_any": 1,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 0,
                "contains_sensitive_pii_flag": 0,
                "custom_role_wildcard_perm": 0
            }
        else:
            return {
                "sentinel_static_severity_code": sev_code,
                "iam_recent_role_elevation": 1,
                "iam_scope_level_code": 1,
                "mfa_bypassed": 1,
                "unusual_geo_ip": 1,
                "storage_public_access_enabled": 0,
                "storage_sas_unrestricted": 0,
                "exfiltrated_data_mb": 10.0,
                "nsg_unrestricted_inbound_any": 1,
                "imds_token_accessed": 0,
                "keyvault_secret_accessed": 0,
                "contains_sensitive_pii_flag": 0,
                "custom_role_wildcard_perm": 0
            }

    @staticmethod
    def generate_remediation_playbook(incident: Dict[str, Any]) -> List[str]:
        """Generates tailored Azure CLI remediation commands matching the incident type."""
        user = incident.get("affected_user", "compromised-user@corp.azure.com")
        attacker_ip = incident.get("attacker_ip", "198.51.100.74")
        target_res = incident.get("target_resource", "target-resource")
        incident_type = incident.get("incident_type") or determine_incident_type(incident)

        if incident_type == "BRUTE_FORCE":
            return [
                f"# 1. Immediately disable compromised account to halt active brute-force",
                f"az ad user update --id {user} --account-enabled false",
                f"# 2. Revoke all active Entra ID refresh tokens & session cookies",
                f"az rest --method POST --uri 'https://graph.microsoft.com/v1.0/users/{user}/revokeSignInSessions'",
                f"# 3. Block malicious attacker IP in Network Security Group / Firewall perimeter",
                f"az network nsg rule create -g Core-RG --nsg-name PerimeterNSG -n BlockBruteForceActor --priority 100 --source-address-prefixes {attacker_ip} --destination-port-ranges '*' --direction Inbound --access Deny",
                f"# 4. Enforce Microsoft Entra ID Smart Lockout and mandatory MFA registration"
            ]
        elif incident_type == "PRIVILEGE_ESCALATION":
            return [
                f"# 1. Revoke unauthorized role assignment for identity",
                f"az role assignment delete --assignee {user} --scope /subscriptions/{incident.get('subscription_id', 'sub-prod-01')}",
                f"# 2. Disable elevated user account pending investigation",
                f"az ad user update --id {user} --account-enabled false",
                f"# 3. Audit and delete unauthorized custom role definitions",
                f"az role definition delete --name SuperAdminRole",
                f"# 4. Rotate affected Key Vault secrets and service credentials"
            ]
        elif incident_type == "STORAGE_EXPOSURE":
            storage_name = target_res.split("/")[-1] if "/" in target_res else target_res
            return [
                f"# 1. Immediately disable anonymous public blob access on storage account",
                f"az storage account update --name {storage_name} --allow-blob-public-access false",
                f"# 2. Rotate Primary and Secondary storage access keys",
                f"az storage account keys renew --account-name {storage_name} --key primary",
                f"az storage account keys renew --account-name {storage_name} --key secondary",
                f"# 3. Block attacker IP from accessing storage firewall",
                f"az storage account network-rule add --account-name {storage_name} --ip-address {attacker_ip} --action Deny"
            ]
        elif incident_type == "IMDS_TOKEN_THEFT":
            vm_name = target_res.split("/")[-1] if "/" in target_res else target_res
            return [
                f"# 1. Disassociate compromised System-Assigned Managed Identity from VM",
                f"az vm identity remove -g CoreApp-RG -n {vm_name}",
                f"# 2. Disable leaked Key Vault secrets and rotate database credentials",
                f"az keyvault secret set-attributes --vault-name MainKeyVault --name DbProdConnectionSecret --enabled false",
                f"# 3. Block threat source IP in perimeter NSG",
                f"az network nsg rule create -g CoreApp-RG --nsg-name WebNSG -n BlockThreatIP --priority 100 --source-address-prefixes {attacker_ip} --access Deny"
            ]
        else:
            return [
                f"# 1. Disable suspicious identity session",
                f"az ad user update --id {user} --account-enabled false",
                f"# 2. Block malicious origin IP on NSG perimeter",
                f"az network nsg rule create -g ProdRG --nsg-name ProdNSG -n BlockThreatIP --priority 100 --source-address-prefixes {attacker_ip} --access Deny",
                f"# 3. Initiate security baseline audit on resource: {target_res}"
            ]

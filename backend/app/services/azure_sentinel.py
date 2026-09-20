"""
Azure Sentinel SIEM Ingestion and Webhook Listener Service.
Handles real-time Sentinel webhook alerts, REST API polling, entity normalization,
and forensic incident classification.
"""

import os
import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel_ingestor")


def determine_incident_type(payload: Dict[str, Any]) -> str:
    """
    Classifies the incident into one of the core cloud forensic incident types:
    - 'BRUTE_FORCE': Credential access, password spraying, failed authentications, account lockouts.
    - 'PRIVILEGE_ESCALATION': IAM role elevation, custom role creation, wildcard permissions.
    - 'IMDS_TOKEN_THEFT': Instance Metadata Service probing, Managed Identity token extraction.
    - 'STORAGE_EXPOSURE': Public blob exposure, unrestricted SAS tokens, data exfiltration.
    - 'NETWORK_ATTACK': NSG port sweeps, unauthorized ingress, DDoS, perimeter scans.
    - 'CLOUD_SECURITY_INCIDENT': Generic fallback.
    """
    # 1. Direct explicit type if specified
    explicit_type = payload.get("incident_type") or payload.get("IncidentType")
    if explicit_type:
        type_upper = str(explicit_type).upper()
        if type_upper in [
            "BRUTE_FORCE", "PRIVILEGE_ESCALATION", "IMDS_TOKEN_THEFT",
            "STORAGE_EXPOSURE", "NETWORK_ATTACK", "CLOUD_SECURITY_INCIDENT"
        ]:
            return type_upper

    # 2. Extract textual cues from title, rule name, description, tactics, and extended properties
    title = (
        payload.get("Title")
        or payload.get("IncidentTitle")
        or payload.get("IncidentName")
        or payload.get("AlertDisplayName")
        or payload.get("title")
        or ""
    )
    rule_name = (
        payload.get("AnalyticsRuleName")
        or payload.get("RuleName")
        or payload.get("analyticRuleName")
        or ""
    )
    description = (
        payload.get("Description")
        or payload.get("IncidentDescription")
        or payload.get("description")
        or ""
    )
    
    # Check nested properties if Sentinel ARM or Logic App schema
    props = payload.get("properties") or payload.get("object", {}).get("properties") or {}
    if isinstance(props, dict):
        title = title or props.get("title", "")
        description = description or props.get("description", "")
        rule_name = rule_name or (props.get("relatedAnalyticRuleIds", [""])[0] if isinstance(props.get("relatedAnalyticRuleIds"), list) and props.get("relatedAnalyticRuleIds") else "")
        alerts = props.get("alerts", [])
        if alerts and isinstance(alerts[0], dict):
            alert_props = alerts[0].get("properties", {})
            title = title or alert_props.get("alertDisplayName", "")
            rule_name = rule_name or alert_props.get("additionalData", {}).get("Analytic Rule Name", "")

    ext_props = payload.get("ExtendedProperties", {}) or payload.get("extendedProperties", {})
    result_type = str(ext_props.get("ResultType", ""))
    failure_reason = str(ext_props.get("FailureReason", ""))

    tactics = payload.get("Tactics", []) or payload.get("tactics", []) or []
    tactics_str = " ".join([str(t) for t in tactics])

    combined_text = f"{title} {rule_name} {description} {tactics_str} {result_type} {failure_reason}".lower()

    # Rule 1: Brute Force / Account Lockout / Credential Access
    bf_keywords = [
        "brute force", "bruteforce", "password guessing", "password spray",
        "account lockout", "lockout detection", "failed sign-in", "failed sign in",
        "failed login", "authentication failure", "50053", "50126", "50057",
        "smart lockout", "credential access", "too many attempts", "entra id - brute force"
    ]
    if any(kw in combined_text for kw in bf_keywords) or result_type in ["50053", "50126", "50057"]:
        return "BRUTE_FORCE"

    # Rule 2: IMDS Token Theft / Metadata API Exploitation
    imds_keywords = [
        "imds", "169.254.169.254", "managed identity", "token theft",
        "instance metadata", "metadata probe", "oauth2/token", "token harvest",
        "system-assigned identity"
    ]
    if any(kw in combined_text for kw in imds_keywords):
        return "IMDS_TOKEN_THEFT"

    # Rule 3: Storage Public Exposure & Data Exfiltration
    storage_keywords = [
        "storage", "blob", "allowblobpublicaccess", "public access",
        "sas token", "blob data", "exfiltration", "mass download",
        "egress spike", "storage account", "container permission"
    ]
    if any(kw in combined_text for kw in storage_keywords):
        return "STORAGE_EXPOSURE"

    # Rule 4: Privilege Escalation & IAM Role Modification
    iam_keywords = [
        "privilege escalation", "role assignment", "custom role", "elevated access",
        "superadmin", "contributor role", "owner role", "role definition",
        "wildcard permission", "iam modification", "rbac elevation", "super admin"
    ]
    if any(kw in combined_text for kw in iam_keywords):
        return "PRIVILEGE_ESCALATION"

    # Rule 5: Network Attack & Perimeter Reconnaissance
    net_keywords = [
        "port sweep", "port scan", "syn flood", "ddos", "unauthorized ingress",
        "network scan", "active scanning", "open nsg", "nsg flow"
    ]
    if any(kw in combined_text for kw in net_keywords):
        return "NETWORK_ATTACK"

    return "CLOUD_SECURITY_INCIDENT"


class AzureSentinelService:
    """Ingestion and enrichment service for Microsoft Sentinel SIEM."""

    def __init__(self):
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.resource_group = os.getenv("AZURE_RESOURCE_GROUP")
        self.workspace_name = os.getenv("AZURE_SENTINEL_WORKSPACE")
        self.live_mode = os.getenv("AZURE_LIVE_MODE", "false").lower() == "true"

    def is_live_mode(self) -> bool:
        """Returns True if configured with live Azure credentials."""
        return bool(self.live_mode and self.tenant_id and self.client_id and self.client_secret)

    def process_webhook_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes an incoming Sentinel webhook (sent from Sentinel Automation Rule / Logic App).
        Normalizes entities, extracts target resources, classifies incident type,
        and preserves original Sentinel metadata.
        """
        # 1. Normalize Incident ID
        incident_id = (
            payload.get("IncidentId")
            or payload.get("IncidentNumber")
            or payload.get("id")
            or payload.get("name")
            or f"INC-AZURE-{uuid.uuid4().hex[:8].upper()}"
        )
        if not str(incident_id).startswith("INC-"):
            incident_id = f"INC-AZURE-{str(incident_id).replace('#', '').strip()}"

        # 2. Extract Title and Properties
        props = payload.get("properties") or payload.get("object", {}).get("properties") or {}
        if not isinstance(props, dict):
            props = {}
        alerts_list = payload.get("Alerts", []) or props.get("alerts", []) or []
        first_alert_title = ""
        first_alert_rule = ""
        if alerts_list and isinstance(alerts_list[0], dict):
            alert_props = alerts_list[0].get("properties", {}) if isinstance(alerts_list[0].get("properties"), dict) else alerts_list[0]
            first_alert_title = alert_props.get("alertDisplayName") or alert_props.get("AlertDisplayName", "")
            first_alert_rule = alert_props.get("additionalData", {}).get("Analytic Rule Name", "")

        title = (
            payload.get("Title")
            or payload.get("IncidentTitle")
            or payload.get("IncidentName")
            or payload.get("AnalyticsRuleName")
            or props.get("title")
            or first_alert_title
            or first_alert_rule
            or "Microsoft Entra ID Security Alert"
        )

        # 3. Analytics Rule & Description
        analytics_rule_name = (
            payload.get("AnalyticsRuleName")
            or first_alert_rule
            or first_alert_title
            or payload.get("RuleName")
            or (props.get("relatedAnalyticRuleIds", [""])[0] if isinstance(props.get("relatedAnalyticRuleIds"), list) and props.get("relatedAnalyticRuleIds") else title)
        )
        description = (
            payload.get("Description")
            or payload.get("IncidentDescription")
            or props.get("description")
            or f"Microsoft Sentinel triggered alert for '{title}'."
        )

        # 4. Severity and Status
        severity = payload.get("Severity") or props.get("severity") or "Medium"
        status = payload.get("Status") or props.get("status") or "Active"
        created_time = (
            payload.get("CreatedTimeUtc")
            or props.get("createdTimeUtc")
            or payload.get("created_at")
            or datetime.utcnow().isoformat() + "Z"
        )
        incident_url = payload.get("IncidentUrl") or props.get("incidentUrl") or ""

        # 5. Incident Classification
        incident_type = determine_incident_type(payload)

        # 6. Entity Extraction
        entities = payload.get("Entities", []) or props.get("entities", []) or []
        ext_props = payload.get("ExtendedProperties", {}) or payload.get("extendedProperties", {}) or {}

        # Default fallback values depending on incident type
        if incident_type == "BRUTE_FORCE":
            affected_user = ext_props.get("UserPrincipalName") or ext_props.get("Account") or "test123@corp.onmicrosoft.com"
            attacker_ip = ext_props.get("ClientIP") or ext_props.get("IPAddress") or "101.0.63.28"
            target_resource = "Microsoft Entra ID (Tenant Directory)"
        else:
            affected_user = "svc-account@corp.azure.com"
            attacker_ip = "198.51.100.74"
            target_resource = f"/subscriptions/{self.subscription_id or 'sub-prod-01'}/resourceGroups/{self.resource_group or 'Core-RG'}"

        for ent in entities:
            if not isinstance(ent, dict):
                continue
            ent_kind = ent.get("Kind", ent.get("kind", ent.get("Type", ent.get("type", ""))))
            
            if ent_kind in ["Account", "User", "Mailbox"]:
                account_name = ent.get("Name") or ent.get("AccountName") or ent.get("accountName") or ent.get("userPrincipalName") or ent.get("DisplayName")
                upn_suffix = ent.get("UPNSuffix") or ent.get("upnSuffix")
                if account_name and upn_suffix and "@" not in str(account_name):
                    affected_user = f"{account_name}@{upn_suffix}"
                elif account_name:
                    affected_user = str(account_name)
                    
            elif ent_kind in ["Ip", "IP", "IpAddress"]:
                attacker_ip = ent.get("Address") or ent.get("ipAddress") or ent.get("address") or attacker_ip
                
            elif ent_kind in ["AzureResource", "Host"]:
                res_id = ent.get("ResourceId") or ent.get("resourceId") or ent.get("HostName") or ent.get("azureResourceId")
                if res_id:
                    target_resource = str(res_id)

        # Also inspect direct fields if passed by custom webhook
        if payload.get("affected_user"):
            affected_user = payload["affected_user"]
        if payload.get("attacker_ip"):
            attacker_ip = payload["attacker_ip"]
        if payload.get("target_resource"):
            target_resource = payload["target_resource"]

        logger.info(f"🚨 Ingested Sentinel Alert [{incident_id}] - Type: {incident_type} | Title: '{title}' (Static Severity: {severity})")

        return {
            "incident_id": incident_id,
            "title": title,
            "analytics_rule_name": analytics_rule_name,
            "description": description,
            "incident_type": incident_type,
            "sentinel_static_severity": severity,
            "status": status,
            "created_at": created_time,
            "incident_url": incident_url,
            "target_resource": target_resource,
            "affected_user": affected_user,
            "attacker_ip": attacker_ip,
            "raw_sentinel_payload": payload
        }

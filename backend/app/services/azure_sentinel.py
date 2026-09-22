"""
Azure Sentinel SIEM Ingestion and Webhook Listener Service.

Handles:
- Microsoft Sentinel incident webhook payloads
- Sentinel incident normalization
- Account/IP/entity extraction
- Custom Details extraction
- Analytics rule identification
- Backward compatibility with simple webhook payloads
"""

import os
import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("sentinel_ingestor")


class AzureSentinelService:
    """Ingestion service for Microsoft Sentinel."""

    def __init__(self):
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

        self.resource_group = os.getenv("AZURE_RESOURCE_GROUP")
        self.workspace_name = os.getenv("AZURE_SENTINEL_WORKSPACE")

        self.live_mode = (
            os.getenv("AZURE_LIVE_MODE", "false").lower() == "true"
        )

    # ------------------------------------------------------------------
    # AZURE / SENTINEL STATUS
    # ------------------------------------------------------------------

    def is_live_mode(self) -> bool:
        """Return True when Azure credentials and live mode are configured."""

        return bool(
            self.live_mode
            and self.tenant_id
            and self.client_id
            and self.client_secret
        )

    # ------------------------------------------------------------------
    # HELPER FUNCTIONS
    # ------------------------------------------------------------------

    @staticmethod
    def _first_value(value: Any, default: Optional[str] = None) -> Optional[str]:
        """
        Extract the first value when Sentinel Custom Details returns
        values as arrays.
        """

        if value is None:
            return default

        if isinstance(value, list):
            if not value:
                return default
            return str(value[0])

        return str(value)

    @staticmethod
    def _get_nested(data: Dict[str, Any], *keys: str) -> Any:
        """Safely retrieve nested dictionary values."""

        current = data

        for key in keys:
            if not isinstance(current, dict):
                return None

            current = current.get(key)

        return current

    # ------------------------------------------------------------------
    # SENTINEL ENTITY EXTRACTION
    # ------------------------------------------------------------------

    def _extract_entities(
        self,
        incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract Account, IP and Azure resource information from
        Sentinel relatedEntities.
        """

        affected_user = None
        attacker_ip = None
        target_resource = None

        entities = incident.get("Entities", [])

        # Actual Sentinel ARM incident payload uses:
        # properties.relatedEntities
        if not entities:
            entities = incident.get("properties", {}).get(
                "relatedEntities",
                []
            )

        if not isinstance(entities, list):
            entities = []

        for entity in entities:

            if not isinstance(entity, dict):
                continue

            properties = entity.get("properties", entity)

            entity_type = (
                entity.get("kind")
                or entity.get("Kind")
                or properties.get("kind")
                or properties.get("entityType")
                or ""
            )

            entity_type = str(entity_type).lower()

            # ----------------------------------------------------------
            # ACCOUNT / USER
            # ----------------------------------------------------------

            if entity_type in [
                "account",
                "user"
            ]:
                affected_user = (
                    properties.get("userPrincipalName")
                    or properties.get("Name")
                    or properties.get("name")
                    or properties.get("accountName")
                    or affected_user
                )

            # Sentinel Account entities sometimes have:
            # properties.accountName
            if not affected_user:
                affected_user = (
                    properties.get("userPrincipalName")
                    or properties.get("accountName")
                )

            # ----------------------------------------------------------
            # IP
            # ----------------------------------------------------------

            if entity_type in [
                "ip",
                "ipaddress",
                "host"
            ]:
                attacker_ip = (
                    properties.get("address")
                    or properties.get("Address")
                    or properties.get("ipAddress")
                    or properties.get("ip")
                    or attacker_ip
                )

            # ----------------------------------------------------------
            # AZURE RESOURCE
            # ----------------------------------------------------------

            if entity_type in [
                "azureresource",
                "azure resource",
                "resource"
            ]:
                target_resource = (
                    properties.get("resourceId")
                    or properties.get("ResourceId")
                    or properties.get("name")
                    or target_resource
                )

        return {
            "affected_user": affected_user,
            "attacker_ip": attacker_ip,
            "target_resource": target_resource
        }

    # ------------------------------------------------------------------
    # CUSTOM DETAILS
    # ------------------------------------------------------------------

    def _extract_custom_details(
        self,
        incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract Custom Details generated by the Sentinel analytics rule.

        Example:

        {
            "UserPrincipalName": ["adam@domain.com"],
            "IPAddress": ["103.x.x.x"],
            "FailedAttempts": ["7"],
            "FirstAttempt": ["..."],
            "LastAttempt": ["..."]
        }
        """

        custom_details: Dict[str, Any] = {}

        properties = incident.get("properties", {})

        alerts = properties.get("alerts", [])

        if not isinstance(alerts, list):
            alerts = []

        for alert in alerts:

            if not isinstance(alert, dict):
                continue

            alert_properties = alert.get("properties", {})

            additional_data = alert_properties.get(
                "additionalData",
                {}
            )

            if not isinstance(additional_data, dict):
                continue

            details = additional_data.get(
                "Custom Details",
                {}
            )

            if isinstance(details, dict):
                custom_details.update(details)

        # Also support a directly supplied Custom Details object
        direct_details = incident.get("Custom Details")

        if isinstance(direct_details, dict):
            custom_details.update(direct_details)

        return custom_details

    # ------------------------------------------------------------------
    # ANALYTICS RULE EXTRACTION
    # ------------------------------------------------------------------

    def _extract_analytics_rule(
        self,
        incident: Dict[str, Any]
    ) -> Optional[str]:
        """Extract Sentinel analytics rule name."""

        properties = incident.get("properties", {})

        alerts = properties.get("alerts", [])

        if isinstance(alerts, list):

            for alert in alerts:

                if not isinstance(alert, dict):
                    continue

                alert_properties = alert.get("properties", {})

                rule_name = (
                    alert_properties.get("alertRule")
                    or alert_properties.get("productComponentName")
                    or alert_properties.get("vendorName")
                )

                if rule_name:
                    return str(rule_name)

        return (
            incident.get("AnalyticsRuleName")
            or incident.get("analytics_rule_name")
            or incident.get("RuleName")
        )

    # ------------------------------------------------------------------
    # INCIDENT TYPE
    # ------------------------------------------------------------------

    @staticmethod
    def determine_incident_type(
        incident: Dict[str, Any]
    ) -> str:
        """
        Determine the incident category from documented Sentinel
        incident information.

        This does not invent an attack type when evidence is unavailable.
        """

        title = str(
            incident.get("title")
            or incident.get("sentinel_title")
            or ""
        ).lower()

        rule = str(
            incident.get("analytics_rule_name")
            or ""
        ).lower()

        description = str(
            incident.get("description")
            or ""
        ).lower()

        text = f"{title} {rule} {description}"

        # --------------------------------------------------------------
        # BRUTE FORCE
        # --------------------------------------------------------------

        if any(
            keyword in text
            for keyword in [
                "brute force",
                "password guessing",
                "account lockout",
                "failed sign-in",
                "failed authentication",
                "repeated authentication",
                "repeated sign-in"
            ]
        ):
            return "BRUTE_FORCE"

        # --------------------------------------------------------------
        # PRIVILEGE ESCALATION
        # --------------------------------------------------------------

        if any(
            keyword in text
            for keyword in [
                "privilege escalation",
                "role assignment",
                "privileged role"
            ]
        ):
            return "PRIVILEGE_ESCALATION"

        # --------------------------------------------------------------
        # IMDS / TOKEN THEFT
        # --------------------------------------------------------------

        if any(
            keyword in text
            for keyword in [
                "imds",
                "managed identity",
                "token theft"
            ]
        ):
            return "IMDS_TOKEN_THEFT"

        # --------------------------------------------------------------
        # STORAGE EXPOSURE
        # --------------------------------------------------------------

        if any(
            keyword in text
            for keyword in [
                "storage exposure",
                "blob exposure",
                "public storage",
                "public access"
            ]
        ):
            return "STORAGE_EXPOSURE"

        return "CLOUD_SECURITY_INCIDENT"

    # ------------------------------------------------------------------
    # MAIN WEBHOOK PROCESSOR
    # ------------------------------------------------------------------

    def process_webhook_payload(
        self,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Normalize a Microsoft Sentinel incident webhook payload.

        Supports both:

        1. Actual Sentinel ARM incident payloads
        2. Simple/custom webhook payloads
        """

        if not isinstance(payload, dict):
            raise ValueError(
                "Sentinel webhook payload must be a JSON object"
            )

        # ==============================================================
        # ACTUAL SENTINEL INCIDENT PROPERTIES
        # ==============================================================

        properties = payload.get("properties", {})

        if not isinstance(properties, dict):
            properties = {}

        # ==============================================================
        # INCIDENT ID
        # ==============================================================

        incident_id = (
            properties.get("incidentNumber")
            or properties.get("incidentId")
            or payload.get("IncidentId")
            or payload.get("incidentId")
            or payload.get("id")
        )

        if not incident_id:
            incident_id = (
                f"INC-AZURE-{uuid.uuid4().hex[:6].upper()}"
            )

        incident_id = str(incident_id)

        # ==============================================================
        # TITLE
        # ==============================================================

        title = (
            properties.get("title")
            or payload.get("Title")
            or payload.get("IncidentName")
            or "Cloud Security Incident"
        )

        title = str(title)

        # ==============================================================
        # DESCRIPTION
        # ==============================================================

        description = (
            properties.get("description")
            or payload.get("Description")
            or ""
        )

        # ==============================================================
        # SEVERITY
        # ==============================================================

        severity = (
            properties.get("severity")
            or payload.get("Severity")
            or "Unknown"
        )

        severity = str(severity)

        # ==============================================================
        # STATUS
        # ==============================================================

        status = (
            properties.get("status")
            or payload.get("Status")
            or "New"
        )

        status = str(status)

        # ==============================================================
        # CREATED TIME
        # ==============================================================

        created_time = (
            properties.get("createdTimeUtc")
            or payload.get("CreatedTimeUtc")
            or payload.get("createdTimeUtc")
            or datetime.utcnow().isoformat() + "Z"
        )

        # ==============================================================
        # UPDATED TIME
        # ==============================================================

        updated_time = (
            properties.get("lastModifiedTimeUtc")
            or payload.get("LastModifiedTimeUtc")
            or created_time
        )

        # ==============================================================
        # ANALYTICS RULE
        # ==============================================================

        analytics_rule_name = self._extract_analytics_rule(
            payload
        )

        # ==============================================================
        # ENTITIES
        # ==============================================================

        entity_data = self._extract_entities(
            payload
        )

        affected_user = entity_data.get(
            "affected_user"
        )

        attacker_ip = entity_data.get(
            "attacker_ip"
        )

        target_resource = entity_data.get(
            "target_resource"
        )

        # ==============================================================
        # CUSTOM DETAILS
        # ==============================================================

        custom_details = self._extract_custom_details(
            payload
        )

        # ==============================================================
        # CUSTOM DETAIL VALUES
        # ==============================================================

        user_principal_name = self._first_value(
            custom_details.get("UserPrincipalName")
        )

        ip_address = self._first_value(
            custom_details.get("IPAddress")
        )

        failed_attempts_raw = self._first_value(
            custom_details.get("FailedAttempts")
        )

        first_attempt = self._first_value(
            custom_details.get("FirstAttempt")
        )

        last_attempt = self._first_value(
            custom_details.get("LastAttempt")
        )

        # ==============================================================
        # CUSTOM DETAILS TAKE PRECEDENCE
        # ==============================================================

        if user_principal_name:
            affected_user = user_principal_name

        if ip_address:
            attacker_ip = ip_address

        # ==============================================================
        # FAILED ATTEMPTS
        # ==============================================================

        failed_attempts = None

        if failed_attempts_raw:

            try:
                failed_attempts = int(
                    failed_attempts_raw
                )
            except (ValueError, TypeError):
                failed_attempts = None

        # ==============================================================
        # INCIDENT CLASSIFICATION
        # ==============================================================

        normalized_for_type = {
            "title": title,
            "description": description,
            "analytics_rule_name": analytics_rule_name or ""
        }

        incident_type = self.determine_incident_type(
            normalized_for_type
        )

        # ==============================================================
        # MITRE INFORMATION
        # ==============================================================

        tactics = properties.get(
            "tactics",
            []
        )

        techniques = properties.get(
            "techniques",
            []
        )

        if not isinstance(tactics, list):
            tactics = []

        if not isinstance(techniques, list):
            techniques = []

        # ==============================================================
        # LOGGING
        # ==============================================================

        logger.info(
            "🚨 Ingested Sentinel Incident [%s]: '%s' "
            "(Severity: %s, Type: %s)",
            incident_id,
            title,
            severity,
            incident_type
        )

        if affected_user:
            logger.info(
                "👤 Affected User: %s",
                affected_user
            )

        if attacker_ip:
            logger.info(
                "🌐 Source IP: %s",
                attacker_ip
            )

        if failed_attempts is not None:
            logger.info(
                "🔐 Failed Attempts: %s",
                failed_attempts
            )

        # ==============================================================
        # NORMALIZED INCIDENT
        # ==============================================================

        return {
            "incident_id": incident_id,

            "title": title,
            "sentinel_title": title,

            "description": description,

            "sentinel_static_severity": severity,
            "severity": severity,

            "status": status,

            "created_at": created_time,
            "created_time_utc": created_time,

            "updated_at": updated_time,
            "last_modified_time_utc": updated_time,

            "analytics_rule_name": analytics_rule_name,

            "incident_type": incident_type,

            "target_resource": target_resource,
            "affected_user": affected_user,
            "attacker_ip": attacker_ip,

            "user_principal_name": user_principal_name,
            "ip_address": ip_address,

            "failed_attempts": failed_attempts,
            "first_attempt": first_attempt,
            "last_attempt": last_attempt,

            "tactics": tactics,
            "techniques": techniques,

            "custom_details": custom_details,

            "raw_sentinel_payload": payload
        }

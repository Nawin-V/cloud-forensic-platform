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
import json
import logging
from typing import Dict, Any, Optional
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
    def _first_value(
        value: Any,
        default: Optional[str] = None
    ) -> Optional[str]:
        """
        Extract the first value when Sentinel Custom Details
        returns values as arrays.
        """

        if value is None:
            return default

        if isinstance(value, list):
            if not value:
                return default

            return str(value[0])

        return str(value)

    @staticmethod
    def _get_nested(
        data: Dict[str, Any],
        *keys: str
    ) -> Any:
        """Safely retrieve nested dictionary values."""

        current = data

        for key in keys:
            if not isinstance(current, dict):
                return None

            current = current.get(key)

        return current

    # ------------------------------------------------------------------
    # SENTINEL PAYLOAD NORMALIZATION
    # ------------------------------------------------------------------

    @staticmethod
    def _get_incident_object(
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Microsoft Sentinel Logic App incident trigger wraps the actual
        Sentinel incident inside the top-level 'object' property.

        Example:

        {
            "eventUniqueId": "...",
            "objectSchemaType": "Incident",
            "objectEventType": "Create",
            "object": {
                "id": "...",
                "name": "...",
                "type": "Microsoft.SecurityInsights/Incidents",
                "properties": {
                    ...
                }
            }
        }

        This method unwraps that object while still supporting
        direct/simple webhook payloads.
        """

        if not isinstance(payload, dict):
            return {}

        incident_object = payload.get("object")

        if isinstance(incident_object, dict):
            return incident_object

        # Backward compatibility:
        # Some webhook callers may send the incident directly.
        return payload

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

        properties = incident.get("properties", {})

        if not isinstance(properties, dict):
            properties = {}

        # Actual Sentinel ARM incident payload:
        # properties.relatedEntities
        entities = properties.get(
            "relatedEntities",
            []
        )

        # Backward compatibility with older/simple payloads.
        if not entities:
            entities = incident.get(
                "Entities",
                []
            )

        if not isinstance(entities, list):
            entities = []

        for entity in entities:

            if not isinstance(entity, dict):
                continue

            entity_properties = entity.get(
                "properties",
                entity
            )

            if not isinstance(entity_properties, dict):
                entity_properties = {}

            entity_type = (
                entity.get("kind")
                or entity.get("Kind")
                or entity_properties.get("kind")
                or entity_properties.get("entityType")
                or ""
            )

            entity_type = str(
                entity_type
            ).lower()

            # ----------------------------------------------------------
            # ACCOUNT / USER
            # ----------------------------------------------------------

            if entity_type in [
                "account",
                "user"
            ]:

                # Preferred: UPN
                affected_user = (
                    entity_properties.get(
                        "userPrincipalName"
                    )
                    or entity_properties.get(
                        "UserPrincipalName"
                    )
                    or affected_user
                )

                # Sentinel Account entity fallback
                if not affected_user:
                    affected_user = (
                        entity_properties.get(
                            "Name"
                        )
                        or entity_properties.get(
                            "name"
                        )
                        or entity_properties.get(
                            "accountName"
                        )
                        or entity_properties.get(
                            "AccountName"
                        )
                    )

                # Some Sentinel Account entities store UPN
                # under additionalData.
                if not affected_user:
                    additional_data = entity_properties.get(
                        "additionalData",
                        {}
                    )

                    if isinstance(
                        additional_data,
                        dict
                    ):
                        affected_user = (
                            additional_data.get(
                                "UserPrincipalName"
                            )
                            or additional_data.get(
                                "userPrincipalName"
                            )
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
                    entity_properties.get(
                        "address"
                    )
                    or entity_properties.get(
                        "Address"
                    )
                    or entity_properties.get(
                        "ipAddress"
                    )
                    or entity_properties.get(
                        "IPAddress"
                    )
                    or entity_properties.get(
                        "ip"
                    )
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
                    entity_properties.get(
                        "resourceId"
                    )
                    or entity_properties.get(
                        "ResourceId"
                    )
                    or entity_properties.get(
                        "name"
                    )
                    or entity_properties.get(
                        "Name"
                    )
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

        Microsoft Sentinel can return Custom Details as a JSON string.

        Example:

        "Custom Details": "{\"UserPrincipalName\":[\"bob@domain.com\"],
        \"IPAddress\":[\"103.x.x.x\"],
        \"FailedAttempts\":[\"9\"],
        \"FirstAttempt\":[\"...\"],
        \"LastAttempt\":[\"...\"]}"
        """

        custom_details: Dict[str, Any] = {}

        properties = incident.get(
            "properties",
            {}
        )

        if not isinstance(properties, dict):
            properties = {}

        alerts = properties.get(
            "alerts",
            []
        )

        if not isinstance(alerts, list):
            alerts = []

        for alert in alerts:

            if not isinstance(alert, dict):
                continue

            alert_properties = alert.get(
                "properties",
                {}
            )

            if not isinstance(alert_properties, dict):
                continue

            additional_data = alert_properties.get(
                "additionalData",
                {}
            )

            if not isinstance(
                additional_data,
                dict
            ):
                continue

            raw_details = additional_data.get(
                "Custom Details"
            )

            if raw_details is None:
                continue

            # ----------------------------------------------------------
            # CASE 1:
            # Custom Details is already a dictionary
            # ----------------------------------------------------------

            if isinstance(
                raw_details,
                dict
            ):
                custom_details.update(
                    raw_details
                )
                continue

            # ----------------------------------------------------------
            # CASE 2:
            # Sentinel returns Custom Details as JSON string
            # ----------------------------------------------------------

            if isinstance(
                raw_details,
                str
            ):

                try:
                    parsed_details = json.loads(
                        raw_details
                    )

                    if isinstance(
                        parsed_details,
                        dict
                    ):
                        custom_details.update(
                            parsed_details
                        )

                except json.JSONDecodeError:
                    logger.warning(
                        "⚠️ Unable to parse Sentinel Custom Details JSON"
                    )

        # --------------------------------------------------------------
        # Backward compatibility:
        # direct Custom Details
        # --------------------------------------------------------------

        direct_details = incident.get(
            "Custom Details"
        )

        if isinstance(
            direct_details,
            dict
        ):
            custom_details.update(
                direct_details
            )

        elif isinstance(
            direct_details,
            str
        ):

            try:
                parsed_direct = json.loads(
                    direct_details
                )

                if isinstance(
                    parsed_direct,
                    dict
                ):
                    custom_details.update(
                        parsed_direct
                    )

            except json.JSONDecodeError:
                pass

        return custom_details

    # ------------------------------------------------------------------
    # ANALYTICS RULE EXTRACTION
    # ------------------------------------------------------------------

    def _extract_analytics_rule(
        self,
        incident: Dict[str, Any]
    ) -> Optional[str]:
        """
        Extract the actual Microsoft Sentinel Analytics Rule name.

        Priority:

        1. additionalData["Analytic Rule Name"]
        2. alertRule
        3. friendlyName
        4. top-level legacy fields
        """

        properties = incident.get(
            "properties",
            {}
        )

        if not isinstance(properties, dict):
            properties = {}

        alerts = properties.get(
            "alerts",
            []
        )

        if isinstance(
            alerts,
            list
        ):

            for alert in alerts:

                if not isinstance(
                    alert,
                    dict
                ):
                    continue

                alert_properties = alert.get(
                    "properties",
                    {}
                )

                if not isinstance(
                    alert_properties,
                    dict
                ):
                    continue

                additional_data = alert_properties.get(
                    "additionalData",
                    {}
                )

                if not isinstance(
                    additional_data,
                    dict
                ):
                    additional_data = {}

                # ------------------------------------------------------
                # Actual Sentinel field from your payload
                # ------------------------------------------------------

                rule_name = additional_data.get(
                    "Analytic Rule Name"
                )

                if rule_name:
                    return str(
                        rule_name
                    )

                # ------------------------------------------------------
                # Other possible Sentinel fields
                # ------------------------------------------------------

                rule_name = (
                    alert_properties.get(
                        "alertRule"
                    )
                    or alert_properties.get(
                        "friendlyName"
                    )
                )

                if rule_name:
                    return str(
                        rule_name
                    )

        # Legacy/simple webhook support
        return (
            incident.get(
                "AnalyticsRuleName"
            )
            or incident.get(
                "analytics_rule_name"
            )
            or incident.get(
                "RuleName"
            )
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
            incident.get(
                "title"
            )
            or incident.get(
                "sentinel_title"
            )
            or ""
        ).lower()

        rule = str(
            incident.get(
                "analytics_rule_name"
            )
            or ""
        ).lower()

        description = str(
            incident.get(
                "description"
            )
            or ""
        ).lower()

        text = (
            f"{title} "
            f"{rule} "
            f"{description}"
        )

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

        Supports:

        1. Microsoft Sentinel Logic App incident trigger payloads
        2. Direct Sentinel ARM incident objects
        3. Simple/custom webhook payloads
        """

        if not isinstance(
            payload,
            dict
        ):
            raise ValueError(
                "Sentinel webhook payload must be a JSON object"
            )

        # ==============================================================
        # IMPORTANT:
        # Microsoft Sentinel Logic App trigger wraps the actual
        # incident inside payload["object"].
        # ==============================================================

        incident = self._get_incident_object(
            payload
        )

        properties = incident.get(
            "properties",
            {}
        )

        if not isinstance(
            properties,
            dict
        ):
            properties = {}

        # ==============================================================
        # INCIDENT ID
        # ==============================================================

        incident_id = (
            properties.get(
                "incidentNumber"
            )
            or properties.get(
                "incidentId"
            )
            or incident.get(
                "IncidentId"
            )
            or incident.get(
                "incidentId"
            )
            or incident.get(
                "name"
            )
            or incident.get(
                "id"
            )
            or payload.get(
                "IncidentId"
            )
            or payload.get(
                "incidentId"
            )
        )

        if not incident_id:
            incident_id = (
                f"INC-AZURE-"
                f"{uuid.uuid4().hex[:6].upper()}"
            )

        incident_id = str(
            incident_id
        )

        # ==============================================================
        # TITLE
        # ==============================================================

        title = (
            properties.get(
                "title"
            )
            or incident.get(
                "Title"
            )
            or incident.get(
                "IncidentName"
            )
            or payload.get(
                "Title"
            )
            or payload.get(
                "IncidentName"
            )
            or "Cloud Security Incident"
        )

        title = str(
            title
        )

        # ==============================================================
        # DESCRIPTION
        # ==============================================================

        description = (
            properties.get(
                "description"
            )
            or incident.get(
                "Description"
            )
            or payload.get(
                "Description"
            )
            or ""
        )

        description = str(
            description
        )

        # ==============================================================
        # SEVERITY
        # ==============================================================

        severity = (
            properties.get(
                "severity"
            )
            or incident.get(
                "Severity"
            )
            or payload.get(
                "Severity"
            )
            or "Unknown"
        )

        severity = str(
            severity
        )

        # ==============================================================
        # STATUS
        # ==============================================================

        status = (
            properties.get(
                "status"
            )
            or incident.get(
                "Status"
            )
            or payload.get(
                "Status"
            )
            or "New"
        )

        status = str(
            status
        )

        # ==============================================================
        # CREATED TIME
        # ==============================================================

        created_time = (
            properties.get(
                "createdTimeUtc"
            )
            or incident.get(
                "CreatedTimeUtc"
            )
            or incident.get(
                "createdTimeUtc"
            )
            or payload.get(
                "CreatedTimeUtc"
            )
            or payload.get(
                "createdTimeUtc"
            )
            or datetime.utcnow().isoformat() + "Z"
        )

        # ==============================================================
        # UPDATED TIME
        # ==============================================================

        updated_time = (
            properties.get(
                "lastModifiedTimeUtc"
            )
            or incident.get(
                "LastModifiedTimeUtc"
            )
            or payload.get(
                "LastModifiedTimeUtc"
            )
            or created_time
        )

        # ==============================================================
        # ANALYTICS RULE
        # ==============================================================

        analytics_rule_name = (
            self._extract_analytics_rule(
                incident
            )
        )

        # ==============================================================
        # ENTITIES
        # ==============================================================

        entity_data = (
            self._extract_entities(
                incident
            )
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

        custom_details = (
            self._extract_custom_details(
                incident
            )
        )

        # ==============================================================
        # CUSTOM DETAIL VALUES
        # ==============================================================

        user_principal_name = (
            self._first_value(
                custom_details.get(
                    "UserPrincipalName"
                )
            )
        )

        ip_address = (
            self._first_value(
                custom_details.get(
                    "IPAddress"
                )
            )
        )

        failed_attempts_raw = (
            self._first_value(
                custom_details.get(
                    "FailedAttempts"
                )
            )
        )

        first_attempt = (
            self._first_value(
                custom_details.get(
                    "FirstAttempt"
                )
            )
        )

        last_attempt = (
            self._first_value(
                custom_details.get(
                    "LastAttempt"
                )
            )
        )

        # ==============================================================
        # CUSTOM DETAILS TAKE PRECEDENCE
        # ==============================================================

        if user_principal_name:
            affected_user = (
                user_principal_name
            )

        if ip_address:
            attacker_ip = (
                ip_address
            )

        # ==============================================================
        # FAILED ATTEMPTS
        # ==============================================================

        failed_attempts = None

        if failed_attempts_raw:

            try:
                failed_attempts = int(
                    failed_attempts_raw
                )

            except (
                ValueError,
                TypeError
            ):
                failed_attempts = None

        # ==============================================================
        # INCIDENT CLASSIFICATION
        # ==============================================================

        normalized_for_type = {
            "title": title,
            "description": description,
            "analytics_rule_name": (
                analytics_rule_name
                or ""
            )
        }

        incident_type = (
            self.determine_incident_type(
                normalized_for_type
            )
        )

        # ==============================================================
        # MITRE INFORMATION
        # ==============================================================

        additional_data = properties.get(
            "additionalData",
            {}
        )

        if not isinstance(
            additional_data,
            dict
        ):
            additional_data = {}

        tactics = (
            additional_data.get(
                "tactics",
                properties.get(
                    "tactics",
                    []
                )
            )
        )

        techniques = (
            additional_data.get(
                "techniques",
                properties.get(
                    "techniques",
                    []
                )
            )
        )

        if not isinstance(
            tactics,
            list
        ):
            tactics = []

        if not isinstance(
            techniques,
            list
        ):
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

        if analytics_rule_name:
            logger.info(
                "📋 Analytics Rule: %s",
                analytics_rule_name
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

            "analytics_rule_name": (
                analytics_rule_name
            ),

            "incident_type": incident_type,

            "target_resource": (
                target_resource
            ),

            "affected_user": (
                affected_user
            ),

            "attacker_ip": (
                attacker_ip
            ),

            "user_principal_name": (
                user_principal_name
            ),

            "ip_address": (
                ip_address
            ),

            "failed_attempts": (
                failed_attempts
            ),

            "first_attempt": (
                first_attempt
            ),

            "last_attempt": (
                last_attempt
            ),

            "tactics": tactics,

            "techniques": techniques,

            "custom_details": (
                custom_details
            ),

            # Preserve the complete Logic App/Sentinel payload
            # for forensic provenance and auditing.
            "raw_sentinel_payload": payload
        }

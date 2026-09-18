"""
Azure Sentinel SIEM Ingestion and Webhook Listener Service.
Handles real-time Sentinel webhook alerts, REST API polling, and simulated incident scenario generation.
"""

import os
import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel_ingestor")


class AzureSentinelService:
    """Ingestion service for Azure Sentinel SIEM."""

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
        Normalizes entities, extracts target resources, and prepares for deep evidence bundling.
        """
        incident_id = payload.get("IncidentId", payload.get("id", f"INC-AZURE-{uuid.uuid4().hex[:6].upper()}"))
        title = payload.get("Title", payload.get("IncidentName", "Suspicious Azure Cloud Activity Alert"))
        severity = payload.get("Severity", "Medium")
        status = payload.get("Status", "Active")
        created_time = payload.get("CreatedTimeUtc", datetime.utcnow().isoformat() + "Z")

        # Extract entities
        entities = payload.get("Entities", [])
        affected_user = "unknown-user@corp.azure.com"
        attacker_ip = "198.51.100.74"
        target_resource = f"/subscriptions/{self.subscription_id or 'sub-prod-01'}/resourceGroups/{self.resource_group or 'Core-RG'}"

        for ent in entities:
            ent_kind = ent.get("Kind", ent.get("kind", ""))
            if ent_kind in ["Account", "User"]:
                affected_user = ent.get("Name", ent.get("userPrincipalName", affected_user))
            elif ent_kind in ["Ip", "IP"]:
                attacker_ip = ent.get("Address", ent.get("ipAddress", attacker_ip))
            elif ent_kind in ["AzureResource", "Host"]:
                target_resource = ent.get("ResourceId", ent.get("resourceId", target_resource))

        logger.info(f"🚨 Ingested Sentinel Alert [{incident_id}]: '{title}' (Static Severity: {severity})")

        return {
            "incident_id": incident_id,
            "title": title,
            "sentinel_static_severity": severity,
            "status": status,
            "created_at": created_time,
            "target_resource": target_resource,
            "affected_user": affected_user,
            "attacker_ip": attacker_ip,
            "raw_sentinel_payload": payload
        }

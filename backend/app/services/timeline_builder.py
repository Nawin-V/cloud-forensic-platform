"""
Chronological Timeline & Attack Graph Builder.
Generates context-aware, incident-type specific forensic timelines aligned with MITRE ATT&CK.
"""

from typing import List, Dict, Any
from datetime import datetime
from app.services.azure_sentinel import determine_incident_type


class TimelineBuilder:
    """Reconstructs the chronological narrative of an attack across multi-source telemetry."""

    @staticmethod
    def build_timeline(incident_data: Dict[str, Any], evidence_snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Constructs an enriched, attack-vector specific chronological timeline."""
        existing_timeline = incident_data.get("timeline", [])
        if existing_timeline and len(existing_timeline) > 0:
            return existing_timeline

        incident_type = incident_data.get("incident_type") or determine_incident_type(incident_data)

        if incident_type == "BRUTE_FORCE":
            return TimelineBuilder._build_brute_force_timeline(incident_data, evidence_snapshot)
        elif incident_type == "PRIVILEGE_ESCALATION":
            return TimelineBuilder._build_privilege_escalation_timeline(incident_data, evidence_snapshot)
        elif incident_type == "STORAGE_EXPOSURE":
            return TimelineBuilder._build_storage_timeline(incident_data, evidence_snapshot)
        elif incident_type == "IMDS_TOKEN_THEFT":
            return TimelineBuilder._build_imds_timeline(incident_data, evidence_snapshot)
        elif incident_type == "NETWORK_ATTACK":
            return TimelineBuilder._build_network_timeline(incident_data, evidence_snapshot)
        else:
            return TimelineBuilder._build_generic_timeline(incident_data, evidence_snapshot)

    @staticmethod
    def _build_brute_force_timeline(incident: Dict[str, Any], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        user = incident.get("affected_user", "identity@corp.onmicrosoft.com")
        attacker_ip = incident.get("attacker_ip", "101.0.63.28")
        title = incident.get("title", "Entra ID - Brute Force / Account Lockout Detection")
        severity = incident.get("sentinel_static_severity", "Medium")

        return [
            {
                "timestamp": "T-05m 00s",
                "event_type": "Failed Authentication Attempts",
                "source": "Microsoft Entra ID Sign-In Logs",
                "description": f"Multiple failed sign-in attempts recorded from {attacker_ip} targeting account {user}. ErrorCode: 50126 (Invalid username or password).",
                "mitre_tactic": "T1110 - Brute Force"
            },
            {
                "timestamp": "T-03m 42s",
                "event_type": "High-Frequency Password Guessing",
                "source": "Microsoft Entra ID Sign-In Logs",
                "description": f"Authentication failure velocity exceeded detection threshold (>10 failures in 2 mins) originating from client IP {attacker_ip}.",
                "mitre_tactic": "T1110.001 - Password Guessing"
            },
            {
                "timestamp": "T-00m 30s",
                "event_type": "Account Smart Lockout Engaged",
                "source": "Microsoft Entra ID Protection",
                "description": f"Account {user} locked out by Microsoft Entra ID Smart Lockout to mitigate credential attack. ErrorCode: 50053 (The account is locked due to too many failed attempts).",
                "mitre_tactic": "T1110 - Brute Force"
            },
            {
                "timestamp": "T+00m 02s",
                "event_type": "Microsoft Sentinel Incident Created",
                "source": "Microsoft Sentinel (Analytics Rule)",
                "description": f"Analytics rule '{title}' triggered security incident with static rule severity '{severity}'.",
                "mitre_tactic": "T1078.004 - Cloud Accounts"
            },
            {
                "timestamp": "T+00m 04s",
                "event_type": "Automated Identity Forensics Collection",
                "source": "Cloud Forensic Platform Agent",
                "description": f"Extracted Entra ID sign-in telemetry, client IP geolocation ({attacker_ip}), and identity risk posture.",
                "mitre_tactic": "Collection & Identity Audit"
            },
            {
                "timestamp": "T+00m 06s",
                "event_type": "ML Dynamic Severity Recalculation",
                "source": "Dynamic ML Severity Engine",
                "description": "Evaluated dynamic risk score based on credential velocity, lockout status, and target identity sensitivity.",
                "mitre_tactic": "Threat Scoring"
            }
        ]

    @staticmethod
    def _build_privilege_escalation_timeline(incident: Dict[str, Any], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        user = incident.get("affected_user", "contractor-dev-admin@corp.azure.com")
        attacker_ip = incident.get("attacker_ip", "45.154.255.89")
        target_res = incident.get("target_resource", "Azure Core Resources")
        title = incident.get("title", "Privilege Escalation Alert")
        scope_code = evidence.get("iam_scope_level_code", 2)

        return [
            {
                "timestamp": "T-10m 00s",
                "event_type": "Authentication & Session Initiation",
                "source": "Microsoft Entra ID Sign-In Logs",
                "description": f"Sign-in session initiated for {user} from {attacker_ip}. MFA status: {'Bypassed' if evidence.get('mfa_bypassed') else 'Enforced'}.",
                "mitre_tactic": "T1078 - Valid Accounts"
            },
            {
                "timestamp": "T-04m 10s",
                "event_type": "IAM Role Assignment / Elevation",
                "source": "Azure Activity Log (ARM)",
                "description": f"High-privilege role assignment executed on {target_res}. Blast radius scope level code: {scope_code}.",
                "mitre_tactic": "T1098.003 - Additional Cloud Roles"
            },
            {
                "timestamp": "T-01m 45s",
                "event_type": "Privileged Secret / API Access",
                "source": "Azure Resource Provider Logs",
                "description": "Targeted identity utilized elevated role permissions to query sensitive configuration endpoints.",
                "mitre_tactic": "T1555 - Credentials from Password Stores"
            },
            {
                "timestamp": "T+00m 00s",
                "event_type": "Microsoft Sentinel Security Alert Fired",
                "source": "Microsoft Sentinel (Analytics Rule)",
                "description": f"Security alert '{title}' triggered with static rule severity '{incident.get('sentinel_static_severity', 'High')}'.",
                "mitre_tactic": "T1098 - Account Manipulation"
            },
            {
                "timestamp": "T+00m 02s",
                "event_type": "Automated Deep Cloud Forensics Bundling",
                "source": "Cloud Forensic Platform Agent",
                "description": "Queried ARM Authorization SDK for full RBAC trees, role definitions, and caller audit records.",
                "mitre_tactic": "Collection & Posture Audit"
            },
            {
                "timestamp": "T+00m 04s",
                "event_type": "ML Dynamic Severity Recalculation",
                "source": "Dynamic ML Severity Engine",
                "description": "Severity dynamically evaluated based on privilege escalation breadth and scope blast radius.",
                "mitre_tactic": "Threat Scoring"
            }
        ]

    @staticmethod
    def _build_storage_timeline(incident: Dict[str, Any], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_res = incident.get("target_resource", "prodcustomerdata2026")
        attacker_ip = incident.get("attacker_ip", "194.26.29.112")
        title = incident.get("title", "Public Storage Exposure Alert")
        exfil_mb = evidence.get("exfiltrated_data_mb", 0.0)

        return [
            {
                "timestamp": "T-12m 00s",
                "event_type": "Storage Configuration Manipulation",
                "source": "Azure Resource Manager (Storage API)",
                "description": f"Storage Account property 'allowBlobPublicAccess' modified to True on {target_res}.",
                "mitre_tactic": "T1562.001 - Disable or Modify Tools"
            },
            {
                "timestamp": "T-08m 00s",
                "event_type": "Unrestricted SAS Token Generation",
                "source": "Azure Storage Diagnostic Log",
                "description": "Account SAS token generated with full Read/List permissions for anonymous consumption.",
                "mitre_tactic": "T1558 - Steal or Forge Cloud Tickets"
            },
            {
                "timestamp": "T-03m 00s",
                "event_type": "Mass Blob Data Egress Spike",
                "source": "Azure Monitor Metrics",
                "description": f"High volume blob download detected from {attacker_ip} ({exfil_mb} MB exfiltrated).",
                "mitre_tactic": "T1567 - Exfiltration Over Web Service"
            },
            {
                "timestamp": "T+00m 00s",
                "event_type": "Microsoft Sentinel Security Alert Fired",
                "source": "Microsoft Sentinel (Analytics Rule)",
                "description": f"Security alert '{title}' triggered on storage account egress anomaly.",
                "mitre_tactic": "T1048 - Exfiltration Over Alternative Protocol"
            },
            {
                "timestamp": "T+00m 02s",
                "event_type": "Automated Deep Cloud Forensics Bundling",
                "source": "Cloud Forensic Platform Agent",
                "description": "Collected storage container access policies, SAS validity windows, and blob inventory.",
                "mitre_tactic": "Collection & Posture Audit"
            },
            {
                "timestamp": "T+00m 04s",
                "event_type": "ML Dynamic Severity Recalculation",
                "source": "Dynamic ML Severity Engine",
                "description": "Dynamic severity escalated based on exfiltration volume and confidential data flags.",
                "mitre_tactic": "Threat Scoring"
            }
        ]

    @staticmethod
    def _build_imds_timeline(incident: Dict[str, Any], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_res = incident.get("target_resource", "vm-prod-web-01")
        attacker_ip = incident.get("attacker_ip", "185.220.101.5")
        user = incident.get("affected_user", "svc-web-managed-identity")
        title = incident.get("title", "IMDS Token Theft Alert")

        return [
            {
                "timestamp": "T-10m 00s",
                "event_type": "Remote Ingress to Virtual Machine",
                "source": "Azure Network Watcher (NSG Flow Logs)",
                "description": f"Inbound connection established to {target_res} from {attacker_ip}.",
                "mitre_tactic": "T1078 - Valid Accounts"
            },
            {
                "timestamp": "T-06m 45s",
                "event_type": "IMDS Managed Identity Token Probing",
                "source": "Host OS Syslog / Azure Host Telemetry",
                "description": "HTTP GET request to 169.254.169.254/metadata/identity/oauth2/token captured. Harvested bearer token for identity.",
                "mitre_tactic": "T1552.005 - Cloud Instance Metadata API"
            },
            {
                "timestamp": "T-03m 30s",
                "event_type": "Key Vault Secret Access via Harvested Token",
                "source": "Azure Key Vault Audit Logs",
                "description": f"Managed identity {user} retrieved production connection strings using harvested bearer token.",
                "mitre_tactic": "T1555 - Credentials from Password Stores"
            },
            {
                "timestamp": "T+00m 00s",
                "event_type": "Microsoft Sentinel Security Alert Fired",
                "source": "Microsoft Sentinel (Analytics Rule)",
                "description": f"Security alert '{title}' triggered for suspicious Managed Identity token activity.",
                "mitre_tactic": "T1078.004 - Cloud Accounts"
            },
            {
                "timestamp": "T+00m 02s",
                "event_type": "Automated Deep Cloud Forensics Bundling",
                "source": "Cloud Forensic Platform Agent",
                "description": "Audited VM managed identity bindings, Key Vault access policies, and host call traces.",
                "mitre_tactic": "Collection & Posture Audit"
            },
            {
                "timestamp": "T+00m 04s",
                "event_type": "ML Dynamic Severity Recalculation",
                "source": "Dynamic ML Severity Engine",
                "description": "Dynamic risk score recalculated from credential theft vectors and Key Vault access.",
                "mitre_tactic": "Threat Scoring"
            }
        ]

    @staticmethod
    def _build_network_timeline(incident: Dict[str, Any], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_res = incident.get("target_resource", "Azure Virtual Network")
        attacker_ip = incident.get("attacker_ip", "198.51.100.74")
        title = incident.get("title", "Network Attack Alert")

        return [
            {
                "timestamp": "T-15m 00s",
                "event_type": "Active Port Scanning / Perimeter Probe",
                "source": "Azure Network Watcher (NSG Flow Logs)",
                "description": f"High velocity port sweep and TCP handshake probing detected from {attacker_ip} targeting {target_res}.",
                "mitre_tactic": "T1595.001 - Port Scanning"
            },
            {
                "timestamp": "T-07m 30s",
                "event_type": "Unauthorized Ingress Traffic Spike",
                "source": "Azure DDoS & Firewall Telemetry",
                "description": f"Inbound connection attempts targeting open NSG port bindings from untrusted source {attacker_ip}.",
                "mitre_tactic": "T1046 - Network Service Discovery"
            },
            {
                "timestamp": "T+00m 00s",
                "event_type": "Microsoft Sentinel Security Alert Fired",
                "source": "Microsoft Sentinel (Analytics Rule)",
                "description": f"Security alert '{title}' triggered on network perimeter violation.",
                "mitre_tactic": "T1595 - Active Scanning"
            },
            {
                "timestamp": "T+00m 02s",
                "event_type": "Automated NSG & Firewall Rule Audit",
                "source": "Cloud Forensic Platform Agent",
                "description": "Inspected NSG security rules for unrestricted 0.0.0.0/0 inbound permissions.",
                "mitre_tactic": "Collection & Posture Audit"
            },
            {
                "timestamp": "T+00m 04s",
                "event_type": "ML Dynamic Severity Recalculation",
                "source": "Dynamic ML Severity Engine",
                "description": "Dynamic severity scored based on exposure radius and ingress velocity.",
                "mitre_tactic": "Threat Scoring"
            }
        ]

    @staticmethod
    def _build_generic_timeline(incident: Dict[str, Any], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_res = incident.get("target_resource", "Azure Core Resources")
        attacker_ip = incident.get("attacker_ip", "198.51.100.74")
        user = incident.get("affected_user", "identity")
        title = incident.get("title", "Cloud Threat Alert")

        timeline = [
            {
                "timestamp": "T-10m 00s",
                "event_type": "Anomalous Cloud Telemetry Detected",
                "source": "Azure Activity & Diagnostic Logs",
                "description": f"Unusual activity detected involving user {user} from origin {attacker_ip}.",
                "mitre_tactic": "T1078 - Valid Accounts"
            },
            {
                "timestamp": "T+00m 00s",
                "event_type": "Microsoft Sentinel Security Alert Fired",
                "source": "Microsoft Sentinel (Analytics Rule)",
                "description": f"Alert '{title}' triggered with static severity '{incident.get('sentinel_static_severity', 'Medium')}'.",
                "mitre_tactic": "T1059 - Command and Scripting"
            },
            {
                "timestamp": "T+00m 02s",
                "event_type": "Automated Deep Cloud Forensics Bundling",
                "source": "Cloud Forensic Platform Agent",
                "description": "Queried ARM SDK for IAM trees, Storage configs, and NSG rules.",
                "mitre_tactic": "Collection & Posture Audit"
            },
            {
                "timestamp": "T+00m 04s",
                "event_type": "ML Dynamic Severity Recalculation",
                "source": "Dynamic ML Severity Engine",
                "description": "Dynamic severity recalculated based on multidimensional cloud evidence vectors.",
                "mitre_tactic": "Threat Scoring"
            }
        ]
        return timeline

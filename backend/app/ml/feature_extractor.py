"""
Feature Extractor and Normalizer for Cloud Incident Dynamic Severity Engine.
Maps bundled forensic evidence into numerical feature vectors for model training and inference.
"""

from typing import Dict, Any, List, Union
import numpy as np
import pandas as pd

# The 13 input features used for dynamic severity scoring
FEATURE_COLUMNS: List[str] = [
    "sentinel_static_severity_code",
    "iam_recent_role_elevation",
    "iam_scope_level_code",
    "mfa_bypassed",
    "unusual_geo_ip",
    "storage_public_access_enabled",
    "storage_sas_unrestricted",
    "exfiltrated_data_mb",
    "nsg_unrestricted_inbound_any",
    "imds_token_accessed",
    "keyvault_secret_accessed",
    "contains_sensitive_pii_flag",
    "custom_role_wildcard_perm",
]

# Human-readable labels for SOC display, charts, and report generation
FEATURE_LABELS: Dict[str, str] = {
    "sentinel_static_severity_code": "Sentinel Base Alert Severity",
    "iam_recent_role_elevation": "Recent IAM Role Elevation",
    "iam_scope_level_code": "IAM Scope Breadth (Subscription/Tenant)",
    "mfa_bypassed": "MFA / Conditional Access Bypass",
    "unusual_geo_ip": "Anomalous Sign-in Geo IP",
    "storage_public_access_enabled": "Storage Blob Public Access Enabled",
    "storage_sas_unrestricted": "Unrestricted Storage SAS Token",
    "exfiltrated_data_mb": "Outbound Data Exfiltration Volume (MB)",
    "nsg_unrestricted_inbound_any": "NSG Unrestricted Inbound (0.0.0.0/0)",
    "imds_token_accessed": "VM IMDS Managed Identity Token Access",
    "keyvault_secret_accessed": "Key Vault Secret Retrieval Detected",
    "contains_sensitive_pii_flag": "Target Resource Holds Sensitive PII",
    "custom_role_wildcard_perm": "Custom IAM Role with Wildcard (*) Permissions",
}

SEVERITY_CODE_MAP: Dict[str, int] = {
    "low": 1,
    "informational": 1,
    "medium": 2,
    "high": 3,
    "critical": 3,
}

SEVERITY_NAME_MAP: Dict[int, str] = {
    1: "Low",
    2: "Medium",
    3: "High",
}

IAM_SCOPE_MAP: Dict[str, int] = {
    "none": 0,
    "resource": 0,
    "resourcegroup": 1,
    "rg": 1,
    "subscription": 2,
    "managementgroup": 3,
    "tenant": 3,
}


def score_to_risk_label(score: float) -> str:
    """Classifies a continuous risk score (0-100) into standard forensic risk tiers."""
    if score >= 85.0:
        return "Critical"
    elif score >= 65.0:
        return "High"
    elif score >= 40.0:
        return "Medium"
    else:
        return "Low"


def parse_sentinel_severity(value: Union[str, int, float]) -> int:
    """Parses static Sentinel severity into integer code (1, 2, or 3)."""
    if isinstance(value, (int, float)):
        val = int(value)
        return max(1, min(3, val))
    if isinstance(value, str):
        cleaned = value.strip().lower()
        return SEVERITY_CODE_MAP.get(cleaned, 1)
    return 1


def parse_iam_scope(value: Union[str, int, float]) -> int:
    """Parses IAM scope hierarchy into numeric code (0 to 3)."""
    if isinstance(value, (int, float)):
        val = int(value)
        return max(0, min(3, val))
    if isinstance(value, str):
        cleaned = value.strip().lower().replace(" ", "").replace("_", "")
        return IAM_SCOPE_MAP.get(cleaned, 0)
    return 0


def extract_features_from_dict(evidence: Dict[str, Any]) -> pd.DataFrame:
    """
    Extracts and standardizes the 13 model features from an evidence dictionary or incident object.
    Returns a single-row pandas DataFrame ready for Scikit-learn / XGBoost inference.
    """
    row: Dict[str, float] = {}

    row["sentinel_static_severity_code"] = float(parse_sentinel_severity(evidence.get("sentinel_static_severity_code", evidence.get("sentinel_severity", 1))))
    row["iam_recent_role_elevation"] = 1.0 if bool(evidence.get("iam_recent_role_elevation", evidence.get("role_elevation", False))) else 0.0
    row["iam_scope_level_code"] = float(parse_iam_scope(evidence.get("iam_scope_level_code", evidence.get("scope_level", 0))))
    row["mfa_bypassed"] = 1.0 if bool(evidence.get("mfa_bypassed", False)) else 0.0
    row["unusual_geo_ip"] = 1.0 if bool(evidence.get("unusual_geo_ip", evidence.get("anomalous_geo", False))) else 0.0
    row["storage_public_access_enabled"] = 1.0 if bool(evidence.get("storage_public_access_enabled", evidence.get("public_storage", False))) else 0.0
    row["storage_sas_unrestricted"] = 1.0 if bool(evidence.get("storage_sas_unrestricted", evidence.get("unrestricted_sas", False))) else 0.0
    
    # Exfiltrated data volume
    exfil = evidence.get("exfiltrated_data_mb", evidence.get("data_exfil_mb", 0.0))
    try:
        row["exfiltrated_data_mb"] = max(0.0, float(exfil))
    except (ValueError, TypeError):
        row["exfiltrated_data_mb"] = 0.0

    row["nsg_unrestricted_inbound_any"] = 1.0 if bool(evidence.get("nsg_unrestricted_inbound_any", evidence.get("open_nsg", False))) else 0.0
    row["imds_token_accessed"] = 1.0 if bool(evidence.get("imds_token_accessed", evidence.get("imds_accessed", False))) else 0.0
    row["keyvault_secret_accessed"] = 1.0 if bool(evidence.get("keyvault_secret_accessed", evidence.get("keyvault_accessed", False))) else 0.0
    row["contains_sensitive_pii_flag"] = 1.0 if bool(evidence.get("contains_sensitive_pii_flag", evidence.get("has_pii", False))) else 0.0
    row["custom_role_wildcard_perm"] = 1.0 if bool(evidence.get("custom_role_wildcard_perm", evidence.get("wildcard_role", False))) else 0.0

    return pd.DataFrame([row], columns=FEATURE_COLUMNS)

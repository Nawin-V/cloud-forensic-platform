"""
Pydantic Schemas for Incident, Evidence Bundle, ML Scoring, and Forensic Reports.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class TimelineEvent(BaseModel):
    timestamp: str = Field(..., description="Timestamp of event or snapshot")
    event_type: str = Field(..., description="Type of event (e.g. Brute Force, Role Elevation)")
    source: str = Field(default="Azure Sentinel", description="Data source or Azure API")
    description: str = Field(..., description="Detailed narrative of what occurred")
    mitre_tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK technique code (e.g. T1078)")


class EvidenceSnapshot(BaseModel):
    # Sentinel baseline
    sentinel_static_severity_code: int = Field(default=1, ge=1, le=3)
    
    # IAM Context
    iam_recent_role_elevation: int = Field(default=0, ge=0, le=1)
    iam_scope_level_code: int = Field(default=0, ge=0, le=3)
    custom_role_wildcard_perm: int = Field(default=0, ge=0, le=1)
    
    # Identity
    mfa_bypassed: int = Field(default=0, ge=0, le=1)
    unusual_geo_ip: int = Field(default=0, ge=0, le=1)
    
    # Storage & Data
    storage_public_access_enabled: int = Field(default=0, ge=0, le=1)
    storage_sas_unrestricted: int = Field(default=0, ge=0, le=1)
    exfiltrated_data_mb: float = Field(default=0.0, ge=0.0)
    contains_sensitive_pii_flag: int = Field(default=0, ge=0, le=1)
    
    # Network & Compute
    nsg_unrestricted_inbound_any: int = Field(default=0, ge=0, le=1)
    imds_token_accessed: int = Field(default=0, ge=0, le=1)
    keyvault_secret_accessed: int = Field(default=0, ge=0, le=1)


class RiskFactor(BaseModel):
    feature_key: str
    label: str
    value: float
    contribution_percentage: float
    explanation: str


class MLScoreResult(BaseModel):
    dynamic_ml_risk_score: float
    dynamic_risk_label: str
    static_severity: str
    static_severity_code: int
    static_baseline_score: float
    severity_delta: float
    is_escalated: bool
    top_risk_factors: List[RiskFactor]
    feature_vector: Dict[str, Any]


class IncidentCreate(BaseModel):
    incident_id: Optional[str] = None
    title: str
    sentinel_static_severity: str = "Medium"
    status: str = "Active"
    target_resource: str
    affected_user: Optional[str] = "svc-account@corp.azure.com"
    attacker_ip: Optional[str] = "198.51.100.74"
    evidence_snapshot: EvidenceSnapshot
    timeline: Optional[List[TimelineEvent]] = []
    remediation_playbook: Optional[List[str]] = []


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    created_at: str
    updated_at: Optional[str] = None
    status: str
    sentinel_static_severity: str
    dynamic_ml_risk_score: float
    dynamic_risk_label: str
    severity_delta: float
    is_escalated: bool
    target_resource: str
    affected_user: str
    attacker_ip: str
    evidence_snapshot: Dict[str, Any]
    top_risk_factors: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    remediation_playbook: List[str]

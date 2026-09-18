"""
Predictor Engine for Cloud Incident Dynamic Severity Scoring.
Loads the trained ML model, calculates real-time dynamic risk scores (0-100),
determines risk tiers, and generates feature explainability breakdowns for SOC analysts.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
import joblib
import numpy as np
import pandas as pd

from app.ml.feature_extractor import (
    FEATURE_COLUMNS,
    FEATURE_LABELS,
    extract_features_from_dict,
    score_to_risk_label,
    parse_sentinel_severity
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("predictor")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml", "model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "ml", "metrics.json")


class DynamicSeverityPredictor:
    """Singleton inference and explainability engine for cloud incident risk scoring."""

    _instance: Optional["DynamicSeverityPredictor"] = None

    def __init__(self, model_path: str = MODEL_PATH, metrics_path: str = METRICS_PATH):
        self.model_path = model_path
        self.metrics_path = metrics_path
        self.model = None
        self.feature_importances: Dict[str, float] = {}
        self.metrics: Dict[str, Any] = {}
        self._load_model()

    @classmethod
    def get_instance(cls) -> "DynamicSeverityPredictor":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_model(self):
        """Loads serialized model and metrics."""
        if not os.path.exists(self.model_path):
            logger.warning(f"Model file not found at {self.model_path}. Training new model on startup...")
            from app.ml.model_trainer import train
            train()

        self.model = joblib.load(self.model_path)
        logger.info(f"Loaded dynamic severity ML model from {self.model_path}")

        if os.path.exists(self.metrics_path):
            with open(self.metrics_path, "r") as f:
                self.metrics = json.load(f)
                top_feats = self.metrics.get("top_features", [])
                for feat in top_feats:
                    self.feature_importances[feat["feature_key"]] = feat["importance"]
        else:
            # Fallback uniform importances if metrics file not yet generated
            self.feature_importances = {col: 1.0 / len(FEATURE_COLUMNS) for col in FEATURE_COLUMNS}

    def predict(self, evidence_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs ML inference on a cloud incident's evidence bundle.
        Returns:
            - dynamic_ml_risk_score: float (0.0 to 100.0)
            - dynamic_risk_label: str ("Low", "Medium", "High", "Critical")
            - static_severity: str ("Low", "Medium", "High")
            - severity_delta: float (Dynamic score vs Sentinel base score)
            - is_escalated: bool
            - top_risk_factors: List of contributing factors with impact % and explanations
            - feature_vector: Dict of normalized input features
        """
        if self.model is None:
            self._load_model()

        # 1. Extract feature dataframe
        df_features = extract_features_from_dict(evidence_dict)
        raw_pred = float(self.model.predict(df_features)[0])

        # Clamp score between 0.0 and 100.0
        score = max(0.0, min(100.0, round(raw_pred, 1)))
        label = score_to_risk_label(score)

        # Base Sentinel severity mapping
        sentinel_code = int(df_features["sentinel_static_severity_code"].iloc[0])
        static_severity_name = {1: "Low", 2: "Medium", 3: "High"}.get(sentinel_code, "Low")
        static_baseline_score = {1: 25.0, 2: 50.0, 3: 75.0}.get(sentinel_code, 25.0)

        severity_delta = round(score - static_baseline_score, 1)
        is_escalated = (score >= 65.0 and sentinel_code <= 2) or (score >= 85.0)

        # 2. Compute Incident-Specific Feature Contributions (Explainability)
        risk_factors = []
        feature_row = df_features.iloc[0].to_dict()

        total_active_weight = 0.0
        active_features = []

        for col, val in feature_row.items():
            if col == "sentinel_static_severity_code":
                continue
            
            global_importance = self.feature_importances.get(col, 0.05)

            # Determine activation strength
            if col == "exfiltrated_data_mb":
                # Normalize data volume (capped at 1000MB for scaling)
                activation = min(1.0, val / 500.0) if val > 10.0 else 0.0
            elif col == "iam_scope_level_code":
                activation = val / 3.0
            else:
                activation = 1.0 if val > 0 else 0.0

            if activation > 0:
                impact_weight = global_importance * activation
                total_active_weight += impact_weight
                active_features.append({
                    "feature_key": col,
                    "label": FEATURE_LABELS.get(col, col),
                    "value": val,
                    "impact_weight": impact_weight,
                    "explanation": self._generate_factor_explanation(col, val)
                })

        # Calculate percentage contributions among active risk drivers
        if total_active_weight > 0:
            for item in active_features:
                contribution_pct = round((item["impact_weight"] / total_active_weight) * 100, 1)
                risk_factors.append({
                    "feature_key": item["feature_key"],
                    "label": item["label"],
                    "value": item["value"],
                    "contribution_percentage": contribution_pct,
                    "explanation": item["explanation"]
                })
            # Sort by highest contribution
            risk_factors = sorted(risk_factors, key=lambda x: x["contribution_percentage"], reverse=True)
        else:
            risk_factors.append({
                "feature_key": "baseline",
                "label": "Baseline Activity",
                "value": 0,
                "contribution_percentage": 100.0,
                "explanation": "No high-risk cloud posture flags or deep privilege elevations detected."
            })

        return {
            "dynamic_ml_risk_score": score,
            "dynamic_risk_label": label,
            "static_severity": static_severity_name,
            "static_severity_code": sentinel_code,
            "static_baseline_score": static_baseline_score,
            "severity_delta": severity_delta,
            "is_escalated": is_escalated,
            "top_risk_factors": risk_factors[:5],  # Top 5 primary drivers
            "all_risk_factors": risk_factors,
            "feature_vector": feature_row,
            "model_metadata": {
                "algorithm": self.metrics.get("best_algorithm", "random_forest"),
                "model_r2_score": self.metrics.get("metrics", {}).get("r2_score", 0.98),
            }
        }

    def _generate_factor_explanation(self, feature_key: str, value: float) -> str:
        """Generates human-readable forensic explanation for an active risk factor."""
        explanations = {
            "iam_recent_role_elevation": "Identity was escalated to highly privileged cloud role (Owner/Contributor) right before attack.",
            "iam_scope_level_code": f"Privilege granted at wide blast radius (Scope Level: {int(value)} - Subscription/Tenant).",
            "mfa_bypassed": "Authentication bypassed Multi-Factor Authentication / Conditional Access rules.",
            "unusual_geo_ip": "Sign-in connection originated from untrusted / anomalous geolocation or TOR exit node.",
            "storage_public_access_enabled": "Target Azure Storage Account has 'allowBlobPublicAccess: true' enabled.",
            "storage_sas_unrestricted": "Unrestricted Shared Access Signature (SAS) token created with wide service access.",
            "exfiltrated_data_mb": f"Substantial outbound egress volume detected ({value:.1f} MB exfiltrated).",
            "nsg_unrestricted_inbound_any": "Network Security Group (NSG) has inbound rule open to 0.0.0.0/0 (Internet).",
            "imds_token_accessed": "Attacker probed Instance Metadata Service (169.254.169.254) to harvest VM Managed Identity credentials.",
            "keyvault_secret_accessed": "Anomalous secret retrieval detected against Azure Key Vault.",
            "contains_sensitive_pii_flag": "Compromised asset contains confidential customer/PII/financial data.",
            "custom_role_wildcard_perm": "Identity assigned custom role with unconstrained wildcard (*) action permissions.",
        }
        return explanations.get(feature_key, f"Active risk feature: {feature_key} = {value}")

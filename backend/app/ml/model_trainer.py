"""
Model Trainer for Cloud Incident Dynamic Severity Engine.
Trains Random Forest and XGBoost regression models on the forensic training dataset,
evaluates R2/RMSE/MAE metrics, extracts feature importances, and serializes the trained model.
"""

import os
import json
import logging
from typing import Dict, Any, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split, cross_val_score, KFold

from app.ml.feature_extractor import FEATURE_COLUMNS, FEATURE_LABELS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("model_trainer")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "incidents_training_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "ml")
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, "model.joblib")
METRICS_SAVE_PATH = os.path.join(MODEL_DIR, "metrics.json")


def load_dataset(csv_path: str = DATA_PATH) -> Tuple[pd.DataFrame, pd.Series]:
    """Loads and validates the training dataset."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training dataset not found at: {csv_path}")

    df = pd.read_csv(csv_path)
    logger.info(f"Loaded {len(df)} records from {csv_path}")

    # Check for missing feature columns
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature columns: {missing}")

    if "dynamic_ml_risk_score" not in df.columns:
        raise ValueError("Dataset is missing target column 'dynamic_ml_risk_score'")

    X = df[FEATURE_COLUMNS].copy()
    y = df["dynamic_ml_risk_score"].copy()

    # Fill any missing values with 0
    X = X.fillna(0.0)
    y = y.fillna(0.0)

    return X, y


def train_models(X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
    """
    Trains Random Forest and XGBoost (or Gradient Boosting) models,
    evaluates performance on 80/20 train/test split and 5-fold CV,
    and returns evaluation metrics + feature importances.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42
    )

    results: Dict[str, Any] = {}

    # 1. Random Forest Regressor
    rf_model = RandomForestRegressor(
        n_estimators=100,
        max_depth=12,
        min_samples_split=3,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=1
    )
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)

    rf_r2 = float(r2_score(y_test, rf_preds))
    rf_rmse = float(np.sqrt(mean_squared_error(y_test, rf_preds)))
    rf_mae = float(mean_absolute_error(y_test, rf_preds))

    # 5-fold cross validation R2
    kfold = KFold(n_splits=5, shuffle=True, random_state=42)
    rf_cv_scores = cross_val_score(rf_model, X, y, cv=kfold, scoring="r2", n_jobs=1)
    rf_cv_r2 = float(np.mean(rf_cv_scores))

    logger.info(f"Random Forest -> Test R2: {rf_r2:.4f}, CV R2: {rf_cv_r2:.4f}, RMSE: {rf_rmse:.4f}, MAE: {rf_mae:.4f}")

    # Feature Importance (Random Forest)
    rf_importances = {}
    for col, imp in zip(FEATURE_COLUMNS, rf_model.feature_importances_):
        rf_importances[col] = {
            "feature_key": col,
            "label": FEATURE_LABELS.get(col, col),
            "importance": round(float(imp), 4),
            "importance_percentage": round(float(imp) * 100, 2)
        }
    sorted_rf_importances = sorted(rf_importances.values(), key=lambda x: x["importance"], reverse=True)

    results["random_forest"] = {
        "model": rf_model,
        "r2_test": rf_r2,
        "r2_cv": rf_cv_r2,
        "rmse": rf_rmse,
        "mae": rf_mae,
        "feature_importances": sorted_rf_importances
    }

    # 2. Gradient Boosting Regressor
    gb_model = GradientBoostingRegressor(
        n_estimators=100,
        learning_rate=0.08,
        max_depth=5,
        subsample=0.85,
        random_state=42
    )
    gb_model.fit(X_train, y_train)
    gb_preds = gb_model.predict(X_test)
    gb_r2 = float(r2_score(y_test, gb_preds))
    gb_rmse = float(np.sqrt(mean_squared_error(y_test, gb_preds)))
    gb_mae = float(mean_absolute_error(y_test, gb_preds))
    gb_cv = float(np.mean(cross_val_score(gb_model, X, y, cv=kfold, scoring="r2", n_jobs=1)))
    
    gb_importances = []
    for col, imp in zip(FEATURE_COLUMNS, gb_model.feature_importances_):
        gb_importances.append({
            "feature_key": col,
            "label": FEATURE_LABELS.get(col, col),
            "importance": round(float(imp), 4),
            "importance_percentage": round(float(imp) * 100, 2)
        })
    sorted_gb_importances = sorted(gb_importances, key=lambda x: x["importance"], reverse=True)

    logger.info(f"Gradient Boosting -> Test R2: {gb_r2:.4f}, CV R2: {gb_cv:.4f}, RMSE: {gb_rmse:.4f}, MAE: {gb_mae:.4f}")
    results["gradient_boosting"] = {
        "model": gb_model,
        "r2_test": gb_r2,
        "r2_cv": gb_cv,
        "rmse": gb_rmse,
        "mae": gb_mae,
        "feature_importances": sorted_gb_importances
    }

    # Select best model based on CV R2 score
    best_algo = "random_forest"
    if results["gradient_boosting"]["r2_cv"] > results["random_forest"]["r2_cv"]:
        best_algo = "gradient_boosting"

    logger.info(f"Selected primary algorithm: {best_algo.upper()} (R2: {results[best_algo]['r2_cv']:.4f})")
    
    # Save the selected model
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(results[best_algo]["model"], MODEL_SAVE_PATH)
    logger.info(f"Serialized model saved to: {MODEL_SAVE_PATH}")

    # Prepare metrics payload for API / Frontend
    metrics_payload = {
        "best_algorithm": best_algo,
        "dataset_samples": len(X),
        "metrics": {
            "r2_score": results[best_algo]["r2_test"],
            "cv_r2_score": results[best_algo]["r2_cv"],
            "rmse": results[best_algo]["rmse"],
            "mae": results[best_algo]["mae"],
        },
        "all_models": {
            "random_forest": {
                "r2_cv": results["random_forest"]["r2_cv"],
                "rmse": results["random_forest"]["rmse"],
                "mae": results["random_forest"]["mae"]
            },
            "gradient_boosting": {
                "r2_cv": results["gradient_boosting"]["r2_cv"],
                "rmse": results["gradient_boosting"]["rmse"],
                "mae": results["gradient_boosting"]["mae"]
            }
        },
        "top_features": results[best_algo]["feature_importances"],
        "feature_columns": FEATURE_COLUMNS
    }

    with open(METRICS_SAVE_PATH, "w") as f:
        json.dump(metrics_payload, f, indent=2)
    logger.info(f"Metrics saved to: {METRICS_SAVE_PATH}")

    return metrics_payload


def train():
    """Main training workflow."""
    X, y = load_dataset()
    return train_models(X, y)


if __name__ == "__main__":
    train()

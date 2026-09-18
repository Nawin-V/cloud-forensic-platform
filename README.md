# 🛡️ Cloud Incident & Forensic Response Platform

An intelligent, end-to-end cloud incident investigation platform bridging **Microsoft Azure Sentinel SIEM** and **Deep Cloud Forensics**.

The platform automatically enriches Sentinel security alerts by querying live Azure Resource Manager (ARM) and Graph APIs for configuration snapshots (IAM roles, storage public access, NSG open ports, VM managed identities), recalibrates true risk using a **Trained Machine Learning Model (Gradient Boosting / Random Forest, R² = 93.9%)**, reconstructs chronological attack timelines, and generates management-ready **Forensic Investigation Reports (PDF / Markdown / HTML)** with actionable Azure CLI remediation scripts.

---

## 🏗️ System Architecture

```mermaid
graph TD
    subgraph "1. Detection & Ingestion Layer"
        A[Azure Sentinel Alert / Webhook] --> B[FastAPI Webhook Listener / REST Poller]
        MOCK[Simulated Incident Generator] --> B
    end

    subgraph "2. Deep Cloud Evidence Hunting"
        B --> C[Azure ARM & Graph SDK Collector]
        C -->|Query IAM Roles| IAM[azure-mgmt-authorization]
        C -->|Query Storage ACLs| STO[azure-mgmt-storage]
        C -->|Query Open NSG Rules| NET[azure-mgmt-network]
        C -->|Query VM IMDS Identity| COMP[azure-mgmt-compute]
    end

    subgraph "3. Machine Learning Intelligence"
        IAM & STO & NET & COMP --> FE[13-Feature Vector Normalizer]
        FE --> ML[Dynamic Severity Model\n(Gradient Boosting / Random Forest)]
        ML --> SC[Dynamic Risk Score: 0 - 100\nRisk Tiers: Low / Med / High / Critical]
        ML --> EXP[Feature Contribution & Explainability Engine]
    end

    subgraph "4. Persistence & Presentation"
        SC & EXP --> DB[(Firebase Cloud Firestore / Local JSON)]
        SC & EXP --> REP[Forensic Report Generator\n(ReportLab PDF / Markdown / HTML)]
        DB --> UI[Interactive SOC React Dashboard]
        REP --> UI
    end
```

---

## 🌟 Key Capabilities

1. **Dynamic ML Severity Scoring**:
   - Overcomes the limitation of static Sentinel rule severity.
   - Evaluates multi-vector cloud parameters (IAM elevation, public blob access, IMDS token harvesting, open NSG ports).
   - Achieves **93.86% $R^2$ accuracy** on 600 realistic cloud forensic records.

2. **Automated Evidence Bundler (Dual-Mode)**:
   - **Live Azure Mode**: Uses official Azure Python SDKs (`azure-mgmt-*`) with an Azure Service Principal to query live tenant states in real-time.
   - **Simulation Mode**: Pre-loaded with realistic high-fidelity attack scenarios (e.g. IMDS token theft, SAS abuse, Ransomware data dump) for offline testing and demos.

3. **Multi-Format Forensic Report Generation**:
   - Instantly generates CISO/management-ready investigation reports.
   - Exports in **PDF** (via ReportLab with summary tables and risk gauges), styled **HTML**, and **Markdown**.
   - Includes step-by-step containment Azure CLI commands.

4. **Interactive SOC Dashboard (React + Vite)**:
   - Dark-mode cyber UI with glassmorphism panels.
   - **Live Evidence Matrix & Rescorer**: Toggle evidence flags with instant dynamic ML score recalculation.
   - **Chronological Attack Timeline**: Vertical visualization mapped to MITRE ATT&CK tactics.
   - **ML Explainability Radar & Bar Charts**: Breakdown of top risk drivers.

---

## 📁 Project Directory Structure

```
.
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── incidents.py               # REST API endpoints (list, detail, rescore, reports)
│   │   ├── data/
│   │   │   ├── incidents_training_dataset.csv # 600-sample training dataset
│   │   │   └── incidents/                 # Local persistent storage mirror
│   │   ├── db/
│   │   │   └── firebase.py                # Cloud Firestore + Local JSON fallback adapter
│   │   ├── ml/
│   │   │   ├── feature_extractor.py       # 13 cloud forensic feature vectorization
│   │   │   ├── model_trainer.py           # Model trainer (Gradient Boosting & Random Forest)
│   │   │   ├── predictor.py               # Real-time inference & feature explainability
│   │   │   ├── model.joblib               # Serialized ML model
│   │   │   └── metrics.json               # Model R2 scores & feature importances
│   │   ├── models/
│   │   │   └── incident.py                # Pydantic schemas
│   │   ├── services/
│   │   │   ├── azure_sentinel.py          # Sentinel webhook & ingestion client
│   │   │   ├── evidence_bundler.py        # ARM SDK collector & mock bundler
│   │   │   ├── timeline_builder.py        # Chronological timeline merger
│   │   │   └── report_generator.py        # ReportLab PDF, Markdown, and HTML compiler
│   │   ├── tests/
│   │   │   ├── test_ml_and_report.py      # Unit tests for ML & reporting
│   │   │   └── test_api.py                # FastAPI integration tests
│   │   └── main.py                        # FastAPI entrypoint with Lifespan & demo seeder
│   ├── requirements.txt
│   └── run.py                             # Backend Uvicorn launcher
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx                 # Header with cloud status & simulation button
│   │   │   ├── MetricsRibbon.jsx          # Top metrics summary ribbon
│   │   │   ├── IncidentList.jsx           # Triage list comparing Static vs Dynamic severity
│   │   │   ├── IncidentDetail.jsx         # Main view with dynamic score gauge & tabs
│   │   │   ├── EvidenceInspector.jsx      # Interactive posture matrix & live rescorer
│   │   │   ├── TimelineViewer.jsx         # Chronological vertical attack timeline
│   │   │   ├── RiskScoreExplainer.jsx     # Recharts feature contribution bar chart
│   │   │   ├── ReportViewer.jsx           # Live report preview & PDF download hub
│   │   │   ├── SettingsModal.jsx          # Cloud integration modal
│   │   │   └── NewIncidentModal.jsx       # Attack scenario simulator
│   │   ├── services/
│   │   │   └── api.js                     # Frontend API client
│   │   ├── App.jsx                        # Main application container
│   │   ├── index.css                      # Cyber dark design system & badges
│   │   └── main.jsx                       # React DOM root
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
└── README.md
```

---

## ⚡ Quick Start Guide

### 1. Start the Backend API Server

```bash
# Navigate to project directory
cd /Volumes/Mac\ A/College/Projects/Cloud-Forensic-Platform

# Activate Python Virtual Environment
source venv/bin/activate

# (Optional) Retrain ML Model & Run All Tests
python backend/app/tests/test_ml_and_report.py
python backend/app/tests/test_api.py

# Launch FastAPI Backend (runs on http://localhost:8000)
python backend/run.py
```

Swagger API documentation is available at: **`http://localhost:8000/docs`**

---

### 2. Start the Frontend React Dashboard

```bash
# In a new terminal tab, navigate to frontend directory
cd /Volumes/Mac\ A/College/Projects/Cloud-Forensic-Platform/frontend

# Install dependencies (if not already installed)
npm install

# Start Vite Development Server (runs on http://localhost:5173)
npm run dev
```

Open **`http://localhost:5173`** in your browser to interact with the live dashboard!

---

## 🔑 Optional: Connecting Live Azure & Firebase

### Connecting to Live Microsoft Azure
Create a `backend/.env` file with your Azure Service Principal credentials:

```env
AZURE_LIVE_MODE=true
AZURE_TENANT_ID="your-azure-tenant-id"
AZURE_CLIENT_ID="your-app-registration-client-id"
AZURE_CLIENT_SECRET="your-client-secret-value"
AZURE_SUBSCRIPTION_ID="your-subscription-id"
AZURE_RESOURCE_GROUP="your-resource-group-name"
AZURE_SENTINEL_WORKSPACE="your-log-analytics-workspace"
```

### Connecting to Google Cloud Firebase (Firestore)
1. Download your `serviceAccountKey.json` from Firebase Console.
2. Place it in `serviceAccountKey.json` at the project root or `backend/`.
3. The platform will automatically connect to Cloud Firestore with zero configuration!

---

## 📊 Evaluation & Benchmarks

- **Trained Model**: Gradient Boosting Regressor (100 estimators, depth=5)
- **Dataset**: 600 verified cloud forensic incidents
- **Test $R^2$ Accuracy**: **`93.86%`**
- **5-Fold Cross-Validation $R^2$**: **`92.88%`**
- **Root Mean Squared Error (RMSE)**: `5.52 points`
- **Mean Absolute Error (MAE)**: `4.05 points`

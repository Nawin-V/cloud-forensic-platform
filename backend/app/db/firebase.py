"""
Firebase Cloud Firestore & Local Persistence Hybrid Adapter.
Connects to Firebase Firestore if credentials are provided;
otherwise falls back seamlessly to local JSON/file storage.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("storage_adapter")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_INCIDENTS_DIR = os.path.join(BASE_DIR, "data", "incidents")
DEFAULT_FIREBASE_KEY = os.path.join(os.path.dirname(BASE_DIR), "serviceAccountKey.json")


class StorageAdapter:
    """Hybrid storage engine supporting Firebase Firestore and Local File Store."""

    _instance: Optional["StorageAdapter"] = None

    def __init__(self, key_path: Optional[str] = None):
        self.key_path = key_path or os.getenv("FIREBASE_CREDENTIALS_PATH", DEFAULT_FIREBASE_KEY)
        self.db = None
        self.using_firebase = False
        os.makedirs(LOCAL_INCIDENTS_DIR, exist_ok=True)
        self._initialize()

    @classmethod
    def get_instance(cls) -> "StorageAdapter":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _initialize(self):
        """Initializes Firebase Firestore if service account key exists and cloud network is reachable."""
        if FIREBASE_AVAILABLE and os.path.exists(self.key_path):
            try:
                # Fast socket connectivity check (0.8s timeout)
                import socket
                socket.create_connection(("firestore.googleapis.com", 443), timeout=0.8).close()

                if not firebase_admin._apps:
                    cred = credentials.Certificate(self.key_path)
                    firebase_admin.initialize_app(cred)
                self.db = firestore.client()
                self.using_firebase = True
                logger.info(f"🔥 Connected to Firebase Cloud Firestore successfully! (Key: {self.key_path})")
                return
            except Exception as e:
                logger.warning(f"Firebase initialization skipped or offline: {e}")

        self.using_firebase = False
        logger.info(f"📁 Operating in Local Storage Mode (Incidents directory: {LOCAL_INCIDENTS_DIR})")


    def is_connected_to_firebase(self) -> bool:
        """Returns True if connected to live Firebase Firestore."""
        return self.using_firebase

    def save_incident(self, incident: Dict[str, Any]) -> bool:
        """Saves or updates an incident document in Firestore and local mirror."""
        inc_id = incident.get("incident_id")
        if not inc_id:
            raise ValueError("Incident must contain 'incident_id'")

        incident["updated_at"] = datetime.utcnow().isoformat() + "Z"
        if "created_at" not in incident:
            incident["created_at"] = incident["updated_at"]

        # 1. Always persist to local storage first for instant sub-millisecond access
        saved_locally = False
        try:
            local_path = os.path.join(LOCAL_INCIDENTS_DIR, f"{inc_id}.json")
            with open(local_path, "w") as f:
                json.dump(incident, f, indent=2)
            saved_locally = True
        except Exception as e:
            logger.error(f"Error writing incident {inc_id} to local storage: {e}")

        # 2. Asynchronously / Safely sync to Firebase Cloud Firestore in background
        if self.using_firebase and self.db:
            try:
                import threading
                def _bg_sync(db_client, doc_id, doc_data):
                    try:
                        db_client.collection("incidents").document(doc_id).set(doc_data, merge=True)
                        logger.info(f"🔥 Mirrored incident {doc_id} to Cloud Firestore")
                    except Exception as err:
                        logger.warning(f"Background Firestore sync warning for {doc_id}: {err}")

                threading.Thread(target=_bg_sync, args=(self.db, inc_id, incident), daemon=True).start()
            except Exception as e:
                logger.error(f"Failed to start Firestore sync thread: {e}")

        return saved_locally

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an incident instantly by its ID from local fast cache."""
        local_path = os.path.join(LOCAL_INCIDENTS_DIR, f"{incident_id}.json")
        if os.path.exists(local_path):
            try:
                with open(local_path, "r") as f:
                    return json.load(f)
            except Exception as err:
                logger.error(f"Error reading local incident {incident_id}: {err}")

        # Fallback to Firestore if not found locally
        if self.using_firebase and self.db:
            try:
                doc = self.db.collection("incidents").document(incident_id).get(timeout=2.0)
                if doc.exists:
                    return doc.to_dict()
            except Exception as e:
                logger.warning(f"Firestore fallback fetch failed for {incident_id}: {e}")

        return None

    def list_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Lists all incidents instantly from local fast storage cache (<1ms)."""
        incidents: List[Dict[str, Any]] = []

        if os.path.exists(LOCAL_INCIDENTS_DIR):
            for filename in os.listdir(LOCAL_INCIDENTS_DIR):
                if filename.endswith(".json"):
                    path = os.path.join(LOCAL_INCIDENTS_DIR, filename)
                    try:
                        with open(path, "r") as f:
                            incidents.append(json.load(f))
                    except Exception as err:
                        logger.error(f"Error reading {path}: {err}")

        return sorted(incidents, key=lambda x: x.get("dynamic_ml_risk_score", 0), reverse=True)[:limit]


    def delete_incident(self, incident_id: str) -> bool:
        """Deletes an incident from storage."""
        if self.using_firebase and self.db:
            try:
                self.db.collection("incidents").document(incident_id).delete(timeout=4.0)
            except Exception as e:
                logger.error(f"Firebase delete error: {e}")


        local_path = os.path.join(LOCAL_INCIDENTS_DIR, f"{incident_id}.json")
        if os.path.exists(local_path):
            os.remove(local_path)
            return True
        return False

    def purge_all_incidents(self) -> int:
        """Deletes all incidents from Firebase Firestore and local filesystem storage."""
        count = 0
        # 1. Purge from Firebase Firestore
        if self.using_firebase and self.db:
            try:
                docs = self.db.collection("incidents").stream()
                for doc in docs:
                    doc.reference.delete()
                    count += 1
                logger.info(f"🔥 Purged {count} incident documents from Cloud Firestore")
            except Exception as e:
                logger.error(f"Error purging Firestore incidents: {e}")

        # 2. Purge local incident files
        local_count = 0
        if os.path.exists(LOCAL_INCIDENTS_DIR):
            for filename in os.listdir(LOCAL_INCIDENTS_DIR):
                if filename.endswith(".json"):
                    try:
                        os.remove(os.path.join(LOCAL_INCIDENTS_DIR, filename))
                        local_count += 1
                    except Exception as err:
                        logger.error(f"Error deleting local file {filename}: {err}")
        logger.info(f"📁 Purged {local_count} local incident cache files")
        return max(count, local_count)


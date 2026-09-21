"""
Firebase Cloud Firestore & Local Persistence Hybrid Adapter.

Primary storage:
    Firebase Cloud Firestore

Fallback storage:
    Local JSON files

Azure App Service:
    Uses FIREBASE_SERVICE_ACCOUNT_JSON environment variable.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

try:
    import firebase_admin
    from firebase_admin import credentials, firestore

    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("storage_adapter")


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_INCIDENTS_DIR = os.path.join(BASE_DIR, "data", "incidents")

DEFAULT_FIREBASE_KEY = os.path.join(
    os.path.dirname(BASE_DIR),
    "serviceAccountKey.json"
)


class StorageAdapter:
    """Hybrid storage engine supporting Firebase Firestore and local fallback."""

    _instance: Optional["StorageAdapter"] = None

    def __init__(self, key_path: Optional[str] = None):
        self.key_path = (
            key_path
            or os.getenv("FIREBASE_CREDENTIALS_PATH")
            or DEFAULT_FIREBASE_KEY
        )

        self.db = None
        self.using_firebase = False

        os.makedirs(LOCAL_INCIDENTS_DIR, exist_ok=True)

        self._initialize()

    @classmethod
    def get_instance(cls) -> "StorageAdapter":
        if cls._instance is None:
            cls._instance = cls()

        return cls._instance

    # ============================================================
    # FIREBASE INITIALIZATION
    # ============================================================

    def _initialize(self):
        """Initialize Firestore using Azure environment credentials."""

        if not FIREBASE_AVAILABLE:
            logger.warning(
                "Firebase Admin SDK is not installed. "
                "Using local storage."
            )
            self.using_firebase = False
            return

        try:
            # ----------------------------------------------------
            # OPTION 1: Azure App Service environment variable
            # ----------------------------------------------------

            service_account_json = os.getenv(
                "FIREBASE_SERVICE_ACCOUNT_JSON"
            )

            if service_account_json:
                logger.info(
                    "🔐 FIREBASE_SERVICE_ACCOUNT_JSON detected."
                )

                try:
                    service_account_info = json.loads(
                        service_account_json
                    )
                except json.JSONDecodeError as e:
                    logger.error(
                        f"Invalid Firebase service account JSON: {e}"
                    )
                    self.using_firebase = False
                    return

                if not firebase_admin._apps:
                    cred = credentials.Certificate(
                        service_account_info
                    )

                    firebase_admin.initialize_app(
                        cred,
                        {
                            "projectId": service_account_info.get(
                                "project_id"
                            )
                        }
                    )

                self.db = firestore.client()
                self.using_firebase = True

                logger.info(
                    "🔥 Connected to Firebase Cloud Firestore "
                    "using FIREBASE_SERVICE_ACCOUNT_JSON."
                )

                return

            # ----------------------------------------------------
            # OPTION 2: Local serviceAccountKey.json
            # ----------------------------------------------------

            if os.path.exists(self.key_path):

                logger.info(
                    f"🔑 Local Firebase key found: {self.key_path}"
                )

                if not firebase_admin._apps:
                    cred = credentials.Certificate(
                        self.key_path
                    )

                    firebase_admin.initialize_app(cred)

                self.db = firestore.client()
                self.using_firebase = True

                logger.info(
                    "🔥 Connected to Firebase Cloud Firestore "
                    "using local service account key."
                )

                return

            # ----------------------------------------------------
            # No Firebase credentials
            # ----------------------------------------------------

            logger.warning(
                "⚠️ No Firebase credentials found."
            )

        except Exception as e:
            logger.exception(
                f"❌ Firebase initialization failed: {e}"
            )

        self.using_firebase = False

        logger.info(
            f"📁 Operating in Local Storage Mode "
            f"(Directory: {LOCAL_INCIDENTS_DIR})"
        )

    # ============================================================
    # STATUS
    # ============================================================

    def is_connected_to_firebase(self) -> bool:
        """Returns True when Firestore is connected."""

        return self.using_firebase and self.db is not None

    # ============================================================
    # SAVE INCIDENT
    # ============================================================

    def save_incident(self, incident: Dict[str, Any]) -> bool:
        """
        Save incident to Firestore and local fallback.

        Firestore write is synchronous so the incident is safely
        persisted before the API request finishes.
        """

        inc_id = incident.get("incident_id")

        if not inc_id:
            raise ValueError(
                "Incident must contain 'incident_id'"
            )

        now = datetime.now(timezone.utc).isoformat()

        incident["updated_at"] = now

        if "created_at" not in incident:
            incident["created_at"] = now

        firestore_saved = False
        local_saved = False

        # --------------------------------------------------------
        # FIRESTORE - PRIMARY STORAGE
        # --------------------------------------------------------

        if self.is_connected_to_firebase():

            try:
                self.db.collection("incidents").document(
                    inc_id
                ).set(
                    incident,
                    merge=True
                )

                firestore_saved = True

                logger.info(
                    f"🔥 Incident {inc_id} saved to Firestore."
                )

            except Exception as e:

                logger.exception(
                    f"❌ Firestore save failed for {inc_id}: {e}"
                )

        # --------------------------------------------------------
        # LOCAL FALLBACK / MIRROR
        # --------------------------------------------------------

        try:

            local_path = os.path.join(
                LOCAL_INCIDENTS_DIR,
                f"{inc_id}.json"
            )

            with open(local_path, "w", encoding="utf-8") as f:
                json.dump(
                    incident,
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str
                )

            local_saved = True

        except Exception as e:

            logger.error(
                f"Local incident save failed for {inc_id}: {e}"
            )

        return firestore_saved or local_saved

    # ============================================================
    # GET INCIDENT
    # ============================================================

    def get_incident(
        self,
        incident_id: str
    ) -> Optional[Dict[str, Any]]:

        """Retrieve incident from Firestore first, then local storage."""

        # --------------------------------------------------------
        # FIRESTORE FIRST
        # --------------------------------------------------------

        if self.is_connected_to_firebase():

            try:

                doc = (
                    self.db
                    .collection("incidents")
                    .document(incident_id)
                    .get()
                )

                if doc.exists:

                    data = doc.to_dict()

                    logger.info(
                        f"🔥 Retrieved incident {incident_id} "
                        f"from Firestore."
                    )

                    return data

            except Exception as e:

                logger.warning(
                    f"Firestore retrieval failed for "
                    f"{incident_id}: {e}"
                )

        # --------------------------------------------------------
        # LOCAL FALLBACK
        # --------------------------------------------------------

        local_path = os.path.join(
            LOCAL_INCIDENTS_DIR,
            f"{incident_id}.json"
        )

        if os.path.exists(local_path):

            try:

                with open(
                    local_path,
                    "r",
                    encoding="utf-8"
                ) as f:

                    return json.load(f)

            except Exception as e:

                logger.error(
                    f"Local incident read failed "
                    f"for {incident_id}: {e}"
                )

        return None

    # ============================================================
    # LIST INCIDENTS
    # ============================================================

    def list_incidents(
        self,
        limit: int = 100
    ) -> List[Dict[str, Any]]:

        """
        Retrieve incidents from Firestore.

        Local files are used as fallback and are merged without
        duplicating incident IDs.
        """

        incidents_by_id: Dict[str, Dict[str, Any]] = {}

        # --------------------------------------------------------
        # FIRESTORE
        # --------------------------------------------------------

        if self.is_connected_to_firebase():

            try:

                docs = (
                    self.db
                    .collection("incidents")
                    .stream()
                )

                for doc in docs:

                    data = doc.to_dict()

                    if data:

                        incident_id = (
                            data.get("incident_id")
                            or doc.id
                        )

                        data["incident_id"] = incident_id

                        incidents_by_id[
                            incident_id
                        ] = data

                logger.info(
                    f"🔥 Loaded {len(incidents_by_id)} "
                    f"incidents from Firestore."
                )

            except Exception as e:

                logger.warning(
                    f"Firestore list failed: {e}"
                )

        # --------------------------------------------------------
        # LOCAL FALLBACK / MIRROR
        # --------------------------------------------------------

        if os.path.exists(LOCAL_INCIDENTS_DIR):

            for filename in os.listdir(
                LOCAL_INCIDENTS_DIR
            ):

                if not filename.endswith(".json"):
                    continue

                path = os.path.join(
                    LOCAL_INCIDENTS_DIR,
                    filename
                )

                try:

                    with open(
                        path,
                        "r",
                        encoding="utf-8"
                    ) as f:

                        incident = json.load(f)

                    incident_id = incident.get(
                        "incident_id"
                    )

                    if incident_id:

                        # Firestore takes priority
                        if incident_id not in incidents_by_id:
                            incidents_by_id[
                                incident_id
                            ] = incident

                except Exception as e:

                    logger.error(
                        f"Error reading local incident "
                        f"{path}: {e}"
                    )

        incidents = list(
            incidents_by_id.values()
        )

        # --------------------------------------------------------
        # SORT BY RISK
        # --------------------------------------------------------

        incidents.sort(
            key=lambda x: float(
                x.get(
                    "dynamic_ml_risk_score",
                    0
                ) or 0
            ),
            reverse=True
        )

        return incidents[:limit]

    # ============================================================
    # DELETE INCIDENT
    # ============================================================

    def delete_incident(
        self,
        incident_id: str
    ) -> bool:

        deleted = False

        # --------------------------------------------------------
        # FIRESTORE
        # --------------------------------------------------------

        if self.is_connected_to_firebase():

            try:

                self.db.collection(
                    "incidents"
                ).document(
                    incident_id
                ).delete()

                deleted = True

                logger.info(
                    f"🔥 Deleted incident "
                    f"{incident_id} from Firestore."
                )

            except Exception as e:

                logger.error(
                    f"Firestore delete failed: {e}"
                )

        # --------------------------------------------------------
        # LOCAL
        # --------------------------------------------------------

        local_path = os.path.join(
            LOCAL_INCIDENTS_DIR,
            f"{incident_id}.json"
        )

        if os.path.exists(local_path):

            try:

                os.remove(local_path)

                deleted = True

            except Exception as e:

                logger.error(
                    f"Local delete failed: {e}"
                )

        return deleted

    # ============================================================
    # PURGE ALL
    # ============================================================

    def purge_all_incidents(self) -> int:

        count = 0

        # --------------------------------------------------------
        # FIRESTORE
        # --------------------------------------------------------

        if self.is_connected_to_firebase():

            try:

                docs = (
                    self.db
                    .collection("incidents")
                    .stream()
                )

                for doc in docs:

                    doc.reference.delete()

                    count += 1

                logger.info(
                    f"🔥 Purged {count} incidents "
                    f"from Firestore."
                )

            except Exception as e:

                logger.error(
                    f"Firestore purge failed: {e}"
                )

        # --------------------------------------------------------
        # LOCAL
        # --------------------------------------------------------

        local_count = 0

        if os.path.exists(
            LOCAL_INCIDENTS_DIR
        ):

            for filename in os.listdir(
                LOCAL_INCIDENTS_DIR
            ):

                if filename.endswith(".json"):

                    try:

                        os.remove(
                            os.path.join(
                                LOCAL_INCIDENTS_DIR,
                                filename
                            )
                        )

                        local_count += 1

                    except Exception as e:

                        logger.error(
                            f"Local delete failed "
                            f"for {filename}: {e}"
                        )

        logger.info(
            f"📁 Purged {local_count} local "
            f"incident files."
        )

        return max(
            count,
            local_count
        )

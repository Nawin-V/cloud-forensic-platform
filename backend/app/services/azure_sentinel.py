def process_webhook_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Processes a Microsoft Sentinel incident payload received through
    the Sentinel incident trigger / Logic App.

    Supports the live Microsoft Sentinel incident schema as well as
    the older flattened/simulated payload format.
    """

    # ---------------------------------------------------------
    # 1. Get Sentinel incident properties
    # ---------------------------------------------------------
    properties = payload.get("properties", {})

    if not isinstance(properties, dict):
        properties = {}

    # ---------------------------------------------------------
    # 2. Incident metadata
    # ---------------------------------------------------------
    raw_id = payload.get("id", "")

    incident_id = (
        properties.get("providerIncidentId")
        or properties.get("incidentNumber")
        or payload.get("IncidentId")
        or raw_id
        or f"INC-AZURE-{uuid.uuid4().hex[:6].upper()}"
    )

    title = (
        properties.get("title")
        or payload.get("Title")
        or payload.get("IncidentName")
        or "Cloud Security Incident"
    )

    severity = (
        properties.get("severity")
        or payload.get("Severity")
        or "Medium"
    )

    status = (
        properties.get("status")
        or payload.get("Status")
        or "New"
    )

    created_time = (
        properties.get("createdTimeUtc")
        or properties.get("firstActivityTimeUtc")
        or payload.get("CreatedTimeUtc")
        or datetime.utcnow().isoformat() + "Z"
    )

    # ---------------------------------------------------------
    # 3. Containers for extracted forensic information
    # ---------------------------------------------------------
    affected_user: Optional[str] = None
    attacker_ip: Optional[str] = None
    failed_attempts: Optional[int] = None
    first_attempt: Optional[str] = None
    last_attempt: Optional[str] = None

    # ---------------------------------------------------------
    # 4. Extract Sentinel related entities
    # ---------------------------------------------------------
    related_entities = properties.get("relatedEntities", [])

    if isinstance(related_entities, list):

        for entity in related_entities:

            if not isinstance(entity, dict):
                continue

            kind = str(
                entity.get("kind")
                or entity.get("Kind")
                or ""
            ).lower()

            entity_properties = entity.get("properties", {})

            if not isinstance(entity_properties, dict):
                entity_properties = {}

            # -------------------------
            # Account entity
            # -------------------------
            if kind in ("account", "user"):

                additional_data = entity_properties.get(
                    "additionalData", {}
                )

                if not isinstance(additional_data, dict):
                    additional_data = {}

                affected_user = (
                    additional_data.get("UserPrincipalName")
                    or entity_properties.get("userPrincipalName")
                    or entity_properties.get("upn")
                    or entity_properties.get("displayName")
                    or affected_user
                )

                # If Sentinel only gives accountName + UPN suffix,
                # reconstruct the complete UPN.
                if (
                    not affected_user
                    or "@" not in str(affected_user)
                ):
                    account_name = (
                        entity_properties.get("accountName")
                        or additional_data.get("AccountName")
                    )

                    upn_suffix = (
                        entity_properties.get("upnSuffix")
                    )

                    if account_name and upn_suffix:
                        affected_user = (
                            f"{account_name}@{upn_suffix}"
                        )

            # -------------------------
            # IP entity
            # -------------------------
            elif kind in ("ip", "ipaddress"):

                attacker_ip = (
                    entity_properties.get("address")
                    or entity_properties.get("ipAddress")
                    or attacker_ip
                )

    # ---------------------------------------------------------
    # 5. Extract alert information
    # ---------------------------------------------------------
    alerts = properties.get("alerts", [])

    if isinstance(alerts, list):

        for alert in alerts:

            if not isinstance(alert, dict):
                continue

            alert_properties = alert.get("properties", {})

            if not isinstance(alert_properties, dict):
                continue

            additional_data = alert_properties.get(
                "additionalData",
                {}
            )

            if not isinstance(additional_data, dict):
                continue

            # -------------------------------------------------
            # Custom Details
            # Sentinel stores these as a JSON string.
            # -------------------------------------------------
            custom_details = additional_data.get(
                "Custom Details"
            )

            if isinstance(custom_details, str):

                try:
                    import json

                    custom_details = json.loads(
                        custom_details
                    )

                except (json.JSONDecodeError, TypeError):
                    custom_details = {}

            if not isinstance(custom_details, dict):
                custom_details = {}

            # -------------------------------------------------
            # UserPrincipalName
            # -------------------------------------------------
            upn_value = custom_details.get(
                "UserPrincipalName"
            )

            if isinstance(upn_value, list):
                upn_value = (
                    upn_value[0]
                    if upn_value
                    else None
                )

            if upn_value:
                affected_user = str(upn_value)

            # -------------------------------------------------
            # IPAddress
            # -------------------------------------------------
            ip_value = custom_details.get(
                "IPAddress"
            )

            if isinstance(ip_value, list):
                ip_value = (
                    ip_value[0]
                    if ip_value
                    else None
                )

            if ip_value:
                attacker_ip = str(ip_value)

            # -------------------------------------------------
            # FailedAttempts
            # -------------------------------------------------
            attempts_value = custom_details.get(
                "FailedAttempts"
            )

            if isinstance(attempts_value, list):
                attempts_value = (
                    attempts_value[0]
                    if attempts_value
                    else None
                )

            if attempts_value is not None:
                try:
                    failed_attempts = int(
                        attempts_value
                    )
                except (ValueError, TypeError):
                    failed_attempts = None

            # -------------------------------------------------
            # First attempt
            # -------------------------------------------------
            first_value = custom_details.get(
                "FirstAttempt"
            )

            if isinstance(first_value, list):
                first_value = (
                    first_value[0]
                    if first_value
                    else None
                )

            if first_value:
                first_attempt = str(first_value)

            # -------------------------------------------------
            # Last attempt
            # -------------------------------------------------
            last_value = custom_details.get(
                "LastAttempt"
            )

            if isinstance(last_value, list):
                last_value = (
                    last_value[0]
                    if last_value
                    else None
                )

            if last_value:
                last_attempt = str(last_value)

    # ---------------------------------------------------------
    # 6. Fallback to flattened/simulated payload
    # ---------------------------------------------------------
    if not affected_user:

        affected_user = (
            payload.get("UserPrincipalName")
            or payload.get("affected_user")
        )

    if not attacker_ip:

        attacker_ip = (
            payload.get("IPAddress")
            or payload.get("attacker_ip")
        )

    if failed_attempts is None:

        attempts = payload.get("FailedAttempts")

        if attempts is not None:

            try:
                failed_attempts = int(attempts)
            except (ValueError, TypeError):
                pass

    if not first_attempt:
        first_attempt = payload.get("FirstAttempt")

    if not last_attempt:
        last_attempt = payload.get("LastAttempt")

    # ---------------------------------------------------------
    # 7. Never fabricate forensic evidence
    # ---------------------------------------------------------
    if not affected_user:
        affected_user = "Not available"

    if not attacker_ip:
        attacker_ip = "Not available"

    # ---------------------------------------------------------
    # 8. Target resource
    # ---------------------------------------------------------
    target_resource = (
        payload.get("target_resource")
        or properties.get("targetResource")
        or "Not available"
    )

    # ---------------------------------------------------------
    # 9. Logging
    # ---------------------------------------------------------
    logger.info(
        f"🚨 Ingested Sentinel Alert "
        f"[{incident_id}]: '{title}' "
        f"(Severity: {severity})"
    )

    logger.info(
        f"👤 Affected User: {affected_user}"
    )

    logger.info(
        f"🌐 Source IP: {attacker_ip}"
    )

    if failed_attempts is not None:
        logger.info(
            f"🔐 Failed Attempts: {failed_attempts}"
        )

    # ---------------------------------------------------------
    # 10. Normalized incident
    # ---------------------------------------------------------
    return {
        "incident_id": str(incident_id),
        "title": title,
        "sentinel_static_severity": severity,
        "status": status,
        "created_at": created_time,
        "target_resource": target_resource,
        "affected_user": affected_user,
        "attacker_ip": attacker_ip,

        # Brute-force forensic fields
        "failed_attempts": failed_attempts,
        "first_attempt": first_attempt,
        "last_attempt": last_attempt,

        # Detection metadata
        "analytics_rule_name": title,
        "mitre_techniques": (
            properties
            .get("additionalData", {})
            .get("techniques", [])
            if isinstance(
                properties.get("additionalData", {}),
                dict
            )
            else []
        ),

        # Preserve original Sentinel evidence
        "raw_sentinel_payload": payload
    }

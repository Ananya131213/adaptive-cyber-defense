"""Rule-based and anomaly-based detection for normalized security events."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sklearn.ensemble import IsolationForest


_RULES_PATH = Path(__file__).with_name("rules.json")
_ENCODED_COMMAND = re.compile(r"(?:^|\s)-(?:enc|encodedcommand)(?:\s|:|$)", re.IGNORECASE)
_SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_configuration() -> dict[str, Any]:
    with _RULES_PATH.open(encoding="utf-8") as rules_file:
        return json.load(rules_file)


def _attributes(event: Mapping[str, Any]) -> Mapping[str, Any]:
    attributes = event.get("attributes", {})
    return attributes if isinstance(attributes, Mapping) else {}


def _source(event: Mapping[str, Any]) -> str:
    return str(event.get("source", "unknown")).lower()


def _event_text(event: Mapping[str, Any]) -> str:
    attributes = _attributes(event)
    values = [event.get("event_type", "")]
    values.extend(
        attributes.get(key, "")
        for key in (
            "process_name",
            "executable",
            "image",
            "process_path",
            "command_line",
            "command",
        )
    )
    return " ".join(str(value) for value in values).lower()


def _event_time(event: Mapping[str, Any]) -> datetime:
    raw_timestamp = event.get("timestamp")
    if isinstance(raw_timestamp, datetime):
        parsed = raw_timestamp
    else:
        value = str(raw_timestamp or "").strip()
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_text(event: Mapping[str, Any]) -> str:
    timestamp = event.get("timestamp", "")
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(timestamp)


def _number(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0


def _principal(event: Mapping[str, Any]) -> str:
    return str(event.get("principal") or _attributes(event).get("user") or "unknown").lower()


def _source_ip(event: Mapping[str, Any]) -> str:
    attributes = _attributes(event)
    return str(attributes.get("source_ip") or attributes.get("src_ip") or "unknown")


def _is_login_failure(event: Mapping[str, Any]) -> bool:
    text = _event_text(event)
    return _source(event) == "authentication" and any(
        phrase in text
        for phrase in (
            "login_failure",
            "login_failed",
            "failed_login",
            "authentication_failure",
            "auth_failure",
        )
    )


def _is_login_success(event: Mapping[str, Any]) -> bool:
    text = _event_text(event)
    return _source(event) == "authentication" and any(
        phrase in text
        for phrase in (
            "login_success",
            "successful_login",
            "authentication_success",
            "auth_success",
        )
    )


def _make_alert(
    event: Mapping[str, Any],
    *,
    alert_name: str,
    severity: str,
    confidence: float,
    mitre: str,
) -> dict[str, Any]:
    timestamp = _timestamp_text(event)
    identifier = str(event.get("event_id") or timestamp)
    digest = hashlib.sha256(f"{alert_name}|{identifier}|{timestamp}".encode("utf-8")).hexdigest()[:16]
    return {
        "alert_id": f"alert-{digest}",
        "alert_name": alert_name,
        "severity": severity,
        "confidence": round(min(1.0, max(0.0, confidence)), 3),
        "timestamp": timestamp,
        "source": _source(event),
        "mitre": mitre,
    }


def _brute_force_alerts(
    events: list[Mapping[str, Any]], rule: Mapping[str, Any]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        if _is_login_failure(event) or _is_login_success(event):
            grouped[(_principal(event), _source_ip(event))].append(event)

    alerts = []
    failure_threshold = int(rule["failure_threshold"])
    window = timedelta(minutes=int(rule["window_minutes"]))
    for activity in grouped.values():
        failed_logins: list[datetime] = []
        ordered = sorted(activity, key=_event_time)
        for event in ordered:
            timestamp = _event_time(event)
            failed_logins = [seen for seen in failed_logins if timestamp - seen <= window]
            if _is_login_failure(event):
                failed_logins.append(timestamp)
            elif len(failed_logins) > failure_threshold:
                alerts.append(
                    _make_alert(
                        event,
                        alert_name=rule["alert_name"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        mitre=rule["mitre"],
                    )
                )
                failed_logins.clear()
    return alerts


def _powershell_alerts(
    events: list[Mapping[str, Any]], rule: Mapping[str, Any]
) -> list[dict[str, Any]]:
    alerts = []
    for event in events:
        if _source(event) != "process":
            continue
        attributes = _attributes(event)
        text = _event_text(event)
        has_encoded_value = attributes.get("encoded_command") not in (None, "", False)
        if "powershell" in text and (has_encoded_value or _ENCODED_COMMAND.search(text)):
            alerts.append(
                _make_alert(
                    event,
                    alert_name=rule["alert_name"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    mitre=rule["mitre"],
                )
            )
    return alerts


def _outbound_bytes(event: Mapping[str, Any]) -> float:
    attributes = _attributes(event)
    for key in ("bytes_out", "bytes_sent", "outbound_bytes", "bytes_transferred", "bytes"):
        if key in attributes:
            return _number(attributes[key])
    return 0.0


def _is_outbound(event: Mapping[str, Any]) -> bool:
    attributes = _attributes(event)
    direction = str(attributes.get("direction", "")).lower()
    if direction:
        return direction in {"out", "outbound", "egress", "upload"}
    return any(word in _event_text(event) for word in ("outbound", "egress", "upload"))


def _exfiltration_alerts(
    events: list[Mapping[str, Any]], rule: Mapping[str, Any]
) -> list[dict[str, Any]]:
    threshold = _number(rule["minimum_outbound_bytes"])
    return [
        _make_alert(
            event,
            alert_name=rule["alert_name"],
            severity=rule["severity"],
            confidence=rule["confidence"],
            mitre=rule["mitre"],
        )
        for event in events
        if _source(event) == "network" and _is_outbound(event) and _outbound_bytes(event) >= threshold
    ]


def _is_admin_role_change(event: Mapping[str, Any]) -> bool:
    text = _event_text(event)
    if "role" not in text or not any(word in text for word in ("change", "grant", "assign", "update", "modify")):
        return False
    attributes = _attributes(event)
    admin_value = attributes.get("is_admin") is True
    role_values = (
        attributes.get("role"),
        attributes.get("new_role"),
        attributes.get("target_role"),
        attributes.get("role_name"),
    )
    return admin_value or "admin" in text or any(
        "admin" in str(value).lower() or "privileged" in str(value).lower()
        for value in role_values
        if value is not None
    )


def _privilege_escalation_alerts(
    events: list[Mapping[str, Any]], rule: Mapping[str, Any]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        if _source(event) == "cloud" and _is_admin_role_change(event):
            grouped[(_principal(event), str(event.get("asset", "unknown")))].append(event)

    alerts = []
    minimum_changes = int(rule["minimum_changes"])
    window = timedelta(minutes=int(rule["window_minutes"]))
    for activity in grouped.values():
        ordered = sorted(activity, key=_event_time)
        recent_changes: list[Mapping[str, Any]] = []
        already_alerted = False
        for event in ordered:
            timestamp = _event_time(event)
            recent_changes = [
                change for change in recent_changes if timestamp - _event_time(change) <= window
            ]
            recent_changes.append(event)
            if len(recent_changes) >= minimum_changes and not already_alerted:
                alerts.append(
                    _make_alert(
                        event,
                        alert_name=rule["alert_name"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        mitre=rule["mitre"],
                    )
                )
                already_alerted = True
            if len(recent_changes) < minimum_changes:
                already_alerted = False
    return alerts


def _anomaly_features(event: Mapping[str, Any]) -> list[float]:
    attributes = _attributes(event)
    command = " ".join(
        str(attributes.get(key, "")) for key in ("command_line", "command", "process_name")
    )
    encoded = bool(attributes.get("encoded_command")) or bool(_ENCODED_COMMAND.search(command))
    role_change = _is_admin_role_change(event)
    severity = _SEVERITY_SCORE.get(str(event.get("severity", "low")).lower(), 0)
    failures = _number(attributes.get("failure_count", attributes.get("failed_attempts", 0)))
    outbound = math.log1p(_outbound_bytes(event))
    return [failures, outbound, min(len(command), 10000), float(encoded), float(role_change), severity]


def _anomaly_alerts(
    events: list[Mapping[str, Any]], configuration: Mapping[str, Any]
) -> list[dict[str, Any]]:
    settings = configuration["anomaly_detection"]
    if not settings.get("enabled", True):
        return []

    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[_source(event)].append(event)

    alerts = []
    minimum_events = int(settings["minimum_events_per_source"])
    for source_events in grouped.values():
        if len(source_events) < minimum_events:
            continue
        features = [_anomaly_features(event) for event in source_events]
        if len({tuple(row) for row in features}) < 2:
            continue
        detector = IsolationForest(
            n_estimators=int(settings["n_estimators"]),
            contamination=settings["contamination"],
            random_state=int(settings["random_state"]),
        )
        detector.fit(features)
        predictions = detector.predict(features)
        anomaly_scores = detector.decision_function(features)
        for event, prediction, score in zip(source_events, predictions, anomaly_scores):
            if prediction != -1:
                continue
            confidence = min(0.95, 0.7 + max(0.0, -float(score)) * 0.25)
            alerts.append(
                _make_alert(
                    event,
                    alert_name=settings["alert_name"],
                    severity=settings["severity"],
                    confidence=confidence,
                    mitre=settings["mitre"],
                )
            )
    return alerts


def detect_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Detect rule matches and source-local anomalies across an event batch."""
    event_batch = [event for event in events if isinstance(event, Mapping)]
    configuration = _load_configuration()
    rules = configuration["rules"]
    alerts: list[dict[str, Any]] = []

    rule_detectors = {
        "brute_force": _brute_force_alerts,
        "suspicious_powershell": _powershell_alerts,
        "data_exfiltration": _exfiltration_alerts,
        "privilege_escalation": _privilege_escalation_alerts,
    }
    for rule_name, detector in rule_detectors.items():
        rule = rules[rule_name]
        if rule.get("enabled", True):
            alerts.extend(detector(event_batch, rule))

    alerts.extend(_anomaly_alerts(event_batch, configuration))
    return alerts


def detect_event(event: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Compatibility entry point accepting one event or a batch of events."""
    if isinstance(event, Mapping):
        return detect_events([event])
    return detect_events(event)
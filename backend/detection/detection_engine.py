"""Detection module entry point for rule and anomaly evaluation."""


def detect_event(event: dict) -> list[dict]:
    """Return alerts for an event; detection strategies are added by the owner."""
    return []
from fastapi import FastAPI, status

from backend.models.schemas import EventAccepted, EventIn

app = FastAPI(
    title="AI-Driven Adaptive Cyber Defense API",
    version="0.1.0",
    description="Starter API for adaptive threat detection and automated threat hunting.",
)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/api/v1/events",
    response_model=EventAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["events"],
)
def submit_event(event: EventIn) -> EventAccepted:
    """Validate and acknowledge an event; analysis is implemented by the team modules."""
    return EventAccepted(accepted=True, event_id=event.event_id)
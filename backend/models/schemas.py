from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime
    source: Literal["authentication", "process", "network", "cloud"]
    event_type: str
    principal: str | None = None
    asset: str | None = None
    severity: Literal["low", "medium", "high", "critical"] = "low"
    attributes: dict[str, Any] = Field(default_factory=dict)


class EventAccepted(BaseModel):
    accepted: bool
    event_id: str
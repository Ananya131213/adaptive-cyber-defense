# API Contract

The backend exposes a versioned JSON API. The contract is intentionally small so frontend and backend work can proceed independently; additions should remain backward-compatible during the hackathon.

## Base URL

Local development: `http://localhost:8000`

Interactive API documentation is available at `/docs` when the backend is running.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness check |
| `POST` | `/api/v1/events` | Submit one normalized event for analysis |

## Submit an Event

`POST /api/v1/events`

Request body:

```json
{
	"event_id": "auth-001",
	"timestamp": "2026-09-26T12:00:00Z",
	"source": "authentication",
	"event_type": "login_failure",
	"principal": "analyst@example.test",
	"asset": "workstation-01",
	"severity": "low",
	"attributes": {
		"source_ip": "192.0.2.10"
	}
}
```

Accepted sources are `authentication`, `process`, `network`, and `cloud`. The current scaffold validates and acknowledges the event; analysis, correlation, and persistence will be implemented in their owned modules.

Successful response (`202 Accepted`):

```json
{
	"accepted": true,
	"event_id": "auth-001"
}
```

Invalid requests return the standard FastAPI `422` validation response. Clients should treat `event_id` as the stable identifier for deduplication and use UTC ISO 8601 timestamps.

## Shared Data Conventions

- JSON field names use `snake_case`.
- Timestamps use ISO 8601 in UTC.
- Event-specific source fields belong in `attributes`; normalized identity and asset fields remain top-level.
- API changes should be reflected here before independently implemented clients or modules depend on them.

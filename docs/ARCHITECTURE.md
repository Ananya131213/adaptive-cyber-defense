# Architecture

## Processing Flow

The platform normalizes security telemetry, detects suspicious activity, groups related alerts into incidents, and presents explainable response recommendations. The response stage is simulation-only in this project.

```text
Logs
  -> Detection Engine
  -> Alert Generation
  -> Correlation Engine
  -> Incident Creation
  -> MITRE Mapping
  -> Risk Scoring
  -> Response Simulation
  -> Dashboard Visualization
```

## Component Responsibilities

- **Log sources:** authentication, endpoint/process, network flow, and cloud audit records. Sample fixtures live in `datasets/`.
- **Detection engine:** applies deterministic rules and anomaly detection (Isolation Forest) to normalized events.
- **Alert generation:** emits event-linked alerts with severity, evidence, and a stable identifier.
- **Correlation engine:** groups related alerts by time, identity, asset, and observable indicators into incidents.
- **Incident creation:** records the correlated events, timeline, and attack graph for investigation.
- **MITRE mapping:** associates evidence with relevant ATT&CK tactics and techniques.
- **Risk scoring:** prioritizes incidents using severity, confidence, asset criticality, and blast-radius signals.
- **Response simulation:** recommends and simulates containment playbooks without operating on real infrastructure.
- **Dashboard:** presents incidents, attack stories, recommended actions, and evaluation metrics.

## Integration Boundaries

`backend/models/schemas.py` and `docs/API_CONTRACT.md` define the initial shared contract. Detection and correlation modules should exchange JSON-serializable records and stable event/alert/incident IDs. The frontend consumes the versioned API; module owners should coordinate schema changes with affected owners and the Team Lead.
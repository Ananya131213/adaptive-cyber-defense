# Team Ownership

The repository is divided by module so each contributor can work independently. Keep shared payload changes in `API_CONTRACT.md` and coordinate them before merging.

| Role | Primary ownership | Responsibilities |
| --- | --- | --- |
| Frontend Developer | `frontend/` | Dashboard pages, reusable components, client services, and presentation data |
| Detection Engineer | `backend/detection/` | Rule-based detection, Isolation Forest scoring, detection fixtures, and alert output |
| Correlation Engineer | `backend/correlation/` | Event grouping, incident creation, timelines, and attack graphs |
| Explainability Engineer | `backend/explainability/` | Alert narratives, MITRE ATT&CK mapping, and risk explanations |
| Response & Evaluation Engineer | `backend/response/`, `backend/evaluation/` | Simulated playbooks, approval/rollback design, audit trail, and evaluation metrics |
| Team Lead | `docs/`, shared contracts, integration and review | Owns cross-team coordination, API and architecture decisions, integration checks, and demo readiness |

The team has five developers: the Team Lead role is an additional coordination responsibility held by one of those developers, not a sixth implementation assignment. The Team Lead should agree on the API/schema contract with module owners before editing shared files. The `backend/models/` schemas are shared: changes there require review from affected module owners. Sample inputs belong in `datasets/`; avoid editing another owner's implementation files without coordinating first.

## Parallel Work Rules

- Prefer module-local files and avoid shared-file churn.
- Keep public function signatures stable once agreed; record changes in the API contract.
- Use synthetic or sanitized logs only.
- Submit small changes scoped to the owned module, with a brief integration note when contracts change.
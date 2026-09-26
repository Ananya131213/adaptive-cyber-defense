# Project Requirements

## Problem Statement

Build an AI-driven adaptive cyber defense platform that ingests:

- Authentication logs
- Endpoint and process logs
- Network flow logs
- Cloud audit logs

The platform should turn heterogeneous security events into understandable, prioritized incidents and safely test response recommendations.

## Core Features

- Rule-based threat detection
- Anomaly detection using Isolation Forest
- Event correlation
- Attack timeline generation
- Attack graph generation
- MITRE ATT&CK mapping
- Explainable alerts
- Risk-based prioritization
- Simulated response playbooks
- Precision, recall, and false-positive-rate evaluation

## Bonus Features

- Graph analytics
- Detection latency comparison
- Asset criticality scoring
- Approval workflow
- Rollback workflow
- Audit logging

## Success Criteria

- Detect multi-stage attacks
- Correlate events into incidents
- Produce attack stories
- Recommend containment actions
- Display metrics on a dashboard

## Scope and Safety

Response playbooks are simulated for the hackathon. The platform must not execute containment actions against real accounts, hosts, or networks without a separately reviewed authorization and approval design.
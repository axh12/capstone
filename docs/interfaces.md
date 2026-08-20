# Component Interfaces

## Digital Twin → Telemetry

Input:

    Modbus request
    Current DT state
    Previous DT state

Output:

    TelemetryEvent

---

## Telemetry → Anomaly Detection

Input:

    TelemetryEvent

Output:

    AnomalyResult

Example:

{
    "event_id": "...",
    "score": 0.82,
    "is_anomaly": true,
    "threshold": 0.15
}

---

## Telemetry → SEM

Input:

    TelemetryEvent
    Optional recent telemetry window

Output:

    CandidateSignature

---

## CandidateSignature → Rule Generator

Input:

    CandidateSignature

Output:

    CandidateRule

---

## AnomalyResult + CandidateRule → Decision Engine

Input:

    AnomalyResult
    CandidateSignature
    CandidateRule

Output:

    Decision

Possible decisions:

    ALLOW
    BLOCK

---

## Decision → IPS

If BLOCK:

    deploy/activate candidate rule

If ALLOW:

    discard candidate rule
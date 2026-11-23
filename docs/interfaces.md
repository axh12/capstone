# Component Interfaces

## Physical Stage 1 ↔ Digital Twin

The Stage 1 connector supports three mediated operations:

    read_state()
    read_commands()
    publish_state(state)

`read_commands()` only accepts configured, allowlisted normal actuator
commands. `publish_state()` writes only to a separate configured state-register
map and is disabled by default.

The real-time runner loads these maps from a JSON file:

    python3 run_automated_response.py \
      --stage1-config stage1_bidirectional.json \
      --stage1-interval 5

Copy `stage1_bidirectional.example.json`, replace its placeholder host and
register addresses with the verified plant map, and set
`enable_writeback` to `true` only after the dedicated status registers have
been confirmed.

---

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

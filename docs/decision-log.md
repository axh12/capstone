# Architecture Decision Log

## ADR-001 — Deterministic Physics Engine

Status: Accepted

The Physics Engine provides deterministic physical behavior and is the sole
Digital Twin simulation engine. External AI services are not required.

---

## ADR-002 — Physical Stage 1 as Reference

Status: Accepted

DT periodically reads physical Stage 1 state.

DT does not write attacker commands to physical Stage 1.

---

## ADR-003 — Mixed Telemetry

Status: Accepted

Telemetry combines process and network information because the anomaly model uses both.

---

## ADR-004 — Parallel AD and SEM

Status: Accepted

Anomaly Detection and SEM execute concurrently.

Rule generation does not wait for anomaly detection.

---

## ADR-005 — Enforcement After AD

Status: Accepted

Decision waits for Anomaly Detection.

NORMAL:
    discard rule

ANOMALY:
    activate rule

---

## ADR-006 — Latency Optimization

Status: Deferred

Initial implementation prioritizes correctness and integration.

Latency optimization will be addressed after the end-to-end pipeline works.

# Development Plan

## Phase 1 — Digital Twin

- [ ] Identify canonical Stage 1 state model
- [ ] Refactor Modbus interface
- [ ] Implement State Manager
- [ ] Implement physical Stage 1 connector
- [ ] Integrate Physics Engine
- [ ] Integrate Mistral Engine
- [ ] Implement state validation
- [ ] Implement fallback
- [ ] Implement structured telemetry

Milestone:

    Modbus command
        ↓
    Digital Twin
        ↓
    realistic state transition
        ↓
    telemetry event

---

## Phase 2 — Anomaly Detection

- [ ] Separate training from inference
- [ ] Serialize trained models
- [ ] Implement runtime Feature Builder
- [ ] Implement Detector API
- [ ] Test against stored telemetry

Milestone:

    Telemetry
        ↓
    20 features
        ↓
    anomaly score

---

## Phase 3 — SEM

- [ ] Runtime signature extraction
- [ ] Signature matching
- [ ] Candidate signature schema

Milestone:

    Telemetry
        ↓
    Candidate Signature

---

## Phase 4 — Rule Generation

- [ ] Candidate signature → Snort rule
- [ ] Rule validation
- [ ] Rule lifecycle management

Milestone:

    Candidate Signature
        ↓
    Candidate Snort Rule

---

## Phase 5 — Decision Engine

- [ ] Parallel execution
- [ ] Wait for AD
- [ ] NORMAL → discard
- [ ] ANOMALY → activate rule

---

## Phase 6 — pfSense/Snort

- [ ] Rule deployment
- [ ] Rule activation
- [ ] Traffic blocking
- [ ] Verify subsequent traffic is blocked

---

## Phase 7 — End-to-End

Test:

    Kali
      ↓
    pfSense
      ↓
    DT
      ↓
    telemetry
      ↓
    AD + SEM
      ↓
    Decision
      ↓
    Main SCADA / DROP
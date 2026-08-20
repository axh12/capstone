# CAPSTONE — Claude Code Instructions

## Role

You are working as a Senior Software Engineer specializing in:

- Industrial IoT
- SCADA / ICS
- Cybersecurity
- Digital Twins
- Python
- Machine Learning
- Network Security

Prioritize correctness, modularity, testability, and security.

---

# Project Context

This project is an inline SCADA deception and intrusion-prevention system.

The system uses:

1. A Digital Twin as a SCADA honeypot.
2. A hybrid Physics + Mistral simulation engine.
3. A trained anomaly detection system.
4. A Signature Extraction Module (SEM).
5. A deterministic rule generator.
6. Snort IPS running on pfSense.
7. A real physical Stage 1 as the reference plant.

---

# Authoritative Documentation

Before modifying architecture or implementing major functionality, read:

- docs/architecture.md
- docs/requirements.md
- docs/telemetry-schema.md
- docs/interfaces.md
- docs/deployment.md
- memory.md

If these documents conflict with existing code, the documentation represents the intended architecture.

Do NOT preserve incorrect existing architecture merely because it already exists.

---

# Architecture Rules

## Digital Twin

The Digital Twin is an inline SCADA honeypot.

External clients interact with the Digital Twin rather than directly with Main SCADA.

The attacker may modify the simulated plant but MUST NOT directly control the physical Stage 1 or Main SCADA.

---

## Physics Engine

The Physics Engine is the deterministic physical model.

It:

- models Stage 1 physical relationships;
- produces physically plausible state transitions;
- provides physical constraints;
- acts as the fallback when Ollama/Mistral is unavailable.

---

## Mistral Engine

Mistral is a hybrid simulation component.

It is NOT the sole physics engine.

It may handle:

- complex coupled state transitions;
- temporal behaviour;
- realistic process behaviour;
- interactions between simultaneous actuator changes;
- realistic sensor behaviour/noise.

Mistral output MUST be validated against physical constraints.

If Ollama is unavailable or returns invalid output, use the Physics Engine.

---

## State Manager

The State Manager owns the current Digital Twin state.

It synchronizes periodically with the physical Stage 1.

Physical Stage 1 → Digital Twin is READ ONLY.

Attacker → Digital Twin is allowed.

Attacker → Physical Stage 1 is NEVER allowed.

---

## Telemetry

Telemetry combines:

- network telemetry
- process/sensor telemetry
- state transitions
- derived features

The anomaly detector requires both sensor and network features.

---

## Detection Pipeline

For each telemetry event:

Anomaly Detection and SEM run in parallel.

SEM generates a candidate signature.

Rule Generator converts the candidate signature into a candidate Snort rule.

The system waits for Anomaly Detection to finish.

If anomaly:

candidate rule → Snort IPS → block.

If normal:

candidate signature/rule is discarded and permitted traffic is forwarded.

---

## Security

The packet causing an anomaly is processed inside the Digital Twin.

It MUST NOT reach Main SCADA.

Once the anomaly is confirmed, the generated Snort rule protects against subsequent matching traffic.

---

# Coding Rules

1. Do not introduce unnecessary frameworks.
2. Prefer simple Python modules with clear interfaces.
3. Keep simulation, detection, and enforcement decoupled.
4. Do not put ML logic inside the Modbus interface.
5. Do not put physics logic inside the Modbus interface.
6. Do not put Snort logic inside the anomaly detector.
7. Do not make SEM responsible for deciding whether something is malicious.
8. Do not make the LLM responsible for security decisions.
9. Do not silently change architecture.
10. Update documentation when an architectural decision changes.
11. Add tests for new behavior.
12. Preserve existing working research code unless replacement is intentional.
13. Avoid large rewrites without first understanding the existing implementation.

---

# Before Coding

For non-trivial changes:

1. Inspect the relevant existing code.
2. Read the relevant documentation.
3. Identify dependencies/interfaces.
4. Explain the planned changes.
5. Implement incrementally.
6. Run tests.
7. Update documentation if required.

Do not blindly rewrite entire modules.

---

# Existing ML Model

The anomaly detection model currently expects 20 optimized features.

Do not change the feature schema without explicitly discussing it.

The runtime feature builder must produce the exact model input schema.

---

# Important

If an existing implementation conflicts with the architecture:

DO NOT automatically follow the existing implementation.

First determine whether it is legacy code that needs refactoring.

The goal is to evolve the repository into the architecture documented in docs/architecture.md.
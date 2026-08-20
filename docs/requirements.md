# System Requirements

## Functional Requirements

### FR-01 Digital Twin

The system shall provide a Modbus TCP Digital Twin representing the first relevant SWaT stage.

### FR-02 Honeypot

The Digital Twin shall accept attacker interaction and produce believable SCADA responses.

### FR-03 Physical Simulation

Modbus commands shall cause corresponding simulated physical state changes.

### FR-04 Multiple State Changes

The simulation shall support simultaneous/interacting actuator changes.

Example:

Opening an inlet and outlet simultaneously must produce a physically consistent flow and level response.

### FR-05 Physical Stage 1 Synchronization

The Digital Twin shall periodically read state from the physical Stage 1.

### FR-06 Isolation

Commands received from external clients shall never directly control the physical Stage 1.

### FR-07 Mistral

The Digital Twin shall support an Ollama-hosted Mistral simulation engine.

### FR-08 Fallback

The Physics Engine shall automatically operate when Mistral/Ollama is unavailable or invalid.

### FR-09 Validation

Mistral-generated state shall be validated against physical constraints.

### FR-10 Telemetry

The Digital Twin shall produce structured telemetry for every relevant interaction/state transition.

### FR-11 Mixed Features

Telemetry shall support both process/sensor and network features required by the anomaly detector.

### FR-12 Anomaly Detection

The system shall perform runtime anomaly detection using the trained model.

### FR-13 SEM

SEM shall generate a candidate behavioral signature.

### FR-14 Rule Generation

The Rule Generator shall convert a candidate signature into an enforceable Snort rule.

### FR-15 Parallel Processing

SEM/rule generation and anomaly detection shall execute concurrently.

### FR-16 Decision

The system shall wait for anomaly detection before deciding whether to activate the candidate rule.

### FR-17 Normal Traffic

Normal traffic shall result in the candidate rule being discarded and permitted traffic being forwarded.

### FR-18 Malicious Traffic

Anomalous traffic shall be blocked and shall not reach Main SCADA.

### FR-19 IPS

Validated rules shall be deployed to Snort IPS on pfSense.

### FR-20 Subsequent Traffic

Once a rule is active, subsequent matching traffic shall be blocked by the IPS.

---

# Non-Functional Requirements

## NFR-01 Reliability

The Digital Twin shall continue operating when Mistral is unavailable.

## NFR-02 Modularity

Simulation, telemetry, detection, signature extraction, rule generation, and enforcement shall remain independently testable.

## NFR-03 Security

The physical Stage 1 shall never be directly controllable by attacker traffic.

## NFR-04 Reproducibility

The anomaly detector and rule generator shall produce deterministic results given identical inputs/configuration.

## NFR-05 Observability

The system shall log:

- network events
- state transitions
- anomaly results
- signatures
- generated rules
- enforcement decisions
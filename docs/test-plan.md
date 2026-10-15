# Current codebase test plan

Scope: the updated `v1` codebase, with the Physics Engine as the sole
simulation engine. Mistral/Ollama is not required.

## Offline regression checks

Run from the repository root:

```sh
dt-venv/bin/python -m unittest discover -s tests -v
```

Existing architecture tests check state bounds, the null Stage 1 connector's
read-only interface, normal-traffic signature discard, source-IP-independent
Modbus rules, and telemetry JSON serialization.

Physics regressions check reproducibility, pump effects on level/flow,
dosing effects on chemistry, and physical bounds across 10,000 ticks.
Passing these tests does not establish complete pipeline correctness.

## Additional tests to implement and execute

| Area | Scenarios | Expected result |
| --- | --- | --- |
| State Manager | Valid patches, rejected patches, snapshot mutation, concurrent updates, NaN/infinity and invalid actuator types | Invalid input cannot mutate state; versions and previous/current snapshots stay consistent; concurrent updates are not lost |
| Modbus Digital Twin | Read registers; supported writes; invalid address/value/function; malformed and truncated requests; client disconnect | Correct responses and process effects; bad requests do not crash the server |
| Physical Stage 1 | Mock register reads, read errors, disconnect, synchronization and attacker writes | Reads synchronize validated state; client closes on failure; no physical write calls occur |
| Telemetry | Before/after commands, timestamps, identifiers, state deltas and network metadata | Events serialize and match the actual state transition |
| Feature extraction | Empty window, known packet sizes/IP pairs, reset, missing sensors and feature ordering | Exactly the model's 20 inputs; independently calculated rates/counts; no stale packets |
| Anomaly detection | Model loading, missing/corrupt artifact, known normal/attack samples and threshold boundaries | Predictable inference/failure; report precision, recall, F1, false-positive rate and confusion matrix on labeled held-out data |
| SEM | Known Modbus attack commands, benign traffic, malformed payloads and repeated behavior from another source IP | Correct behavioral signature; malformed input handled; matching does not depend solely on source IP |
| Rules | Candidate generation/discard/activation, duplicates, expiration, unrelated candidates and Snort syntax validation | Only approved rules become active; unrelated candidates remain inactive; Snort accepts generated rules |
| Orchestrator | Controlled normal/anomalous detector results, delayed AD/SEM, component failures | Normal traffic discards candidate; anomaly activates rule; enforcement waits for classification; failure behavior is explicit |
| Performance | Increasing packet rates, long-running windows and repeated start/stop | Measure throughput, p95/p99 decision latency, memory growth and dropped events against agreed targets |

## Lab integration and end-to-end acceptance

These require the configured Kali, Ubuntu, pfSense/Snort and mock SCADA lab;
they have not been established by the offline tests.

1. Send benign Modbus traffic through pfSense to the Digital Twin. Confirm
   valid telemetry, NORMAL classification, candidate discard and forwarding
   to Main SCADA.
2. Send a controlled anomalous transaction to the Digital Twin. Confirm
   ANOMALY classification, behavioral rule generation and activation, and
   prove with destination capture/logs that the triggering transaction is
   never forwarded to Main SCADA.
3. Repeat matching traffic, including from another source IP. Confirm Snort
   drops it and unrelated benign traffic still passes.
4. Confirm Kali has no direct route to Main SCADA or Physical Stage 1 and
   that attacker commands never write to Physical Stage 1.
5. Interrupt Stage 1 connectivity and detection/enforcement components in
   turn. Record actual recovery and forwarding behavior; compare it with
   the intended failure policy before approving deployment.

Use an isolated test lab and temporary rule files for integration checks.
Retain packet captures, telemetry, classification results and Snort logs as
evidence. Detection accuracy and latency acceptance thresholds still need
to be agreed for the project's dataset and hardware.

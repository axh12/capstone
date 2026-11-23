# An Inline SCADA Digital Twin Honeypot with Anomaly-Gated Intrusion Prevention

**Author Name(s)**  
Department / Institution  
City, Country  
Email address(es)

## Abstract

Industrial control systems (ICS) combine network protocols with physical processes, making cyber attacks capable of producing both network and process-level effects. This paper presents the design of an integrated SCADA security prototype that combines an isolated digital twin honeypot, mixed network and process telemetry, machine-learning anomaly detection, behavioral signature extraction, rule generation, and Snort-based enforcement. The digital twin accepts Modbus TCP interactions and models state changes without forwarding attacker commands to the physical Stage 1. Telemetry is provided to anomaly detection and the Signature Extraction Module (SEM); SEM and the rule generator produce a candidate rule while anomaly detection evaluates the event. A decision engine activates the candidate only when an anomaly is reported. The repository also includes a real-time ensemble implementation based on Isolation Forest, Local Outlier Factor, and a normal-baseline z-score, plus a separate firewall-management integration path. Project documentation reports 95.65% recall and 82.37% precision for the anomaly detector; these values are reported as project-provided results and are not independently reproducible from the artifacts inspected for this draft. The paper describes the architecture, methods, implementation, evaluation evidence, limitations, and a reproducible evaluation plan. The prototype demonstrates a modular approach to safe cyber-physical attack observation and anomaly-gated response, while deployment-level effectiveness requires further controlled testing.

**Index Terms—** industrial control system security, SCADA, digital twin, honeypot, Modbus TCP, anomaly detection, intrusion prevention, Snort.

## I. Introduction

Industrial control systems monitor and control physical processes through sensors, actuators, programmable logic controllers, and supervisory control and data acquisition (SCADA) software. An attack against such systems may alter process measurements, issue unauthorized control commands, or generate unusual network activity. Detection systems that observe network traffic alone may miss the physical consequences of an attack, while process-only monitoring may omit useful evidence about the origin and structure of malicious communication.

This project addresses the problem with an integrated architecture combining a SCADA digital twin, process and network telemetry, anomaly detection, attack signature extraction, candidate rule generation, and intrusion prevention. The digital twin acts as a honeypot that absorbs external Modbus TCP interactions and simulates process consequences. The architecture is designed so that untrusted commands affect the virtual plant and cannot directly control the physical Stage 1. A decision engine gates candidate rule activation on the anomaly detector’s result.

The contributions of this work are: 1) an isolated cyber-physical honeypot design that produces process-aware telemetry; 2) a modular detection and response pipeline combining anomaly detection with signature-based rule generation; and 3) a documented implementation containing an ensemble detector and an anomaly-gated decision contract. The project materials describe both the target Snort/pfSense enforcement path and an integration module that can apply firewall rules. These paths are related but should not be treated as identical implementations; the distinction is made explicit in this paper.

## II. Related Work

Digital twins provide virtual representations of physical systems and can support monitoring, simulation, and security experimentation. In ICS security, a digital twin can also serve as a deception environment in which suspicious commands can be observed without exposing a live process to attacker control. Network intrusion detection systems commonly use signatures to identify known patterns and anomaly detection to identify deviations from learned baselines. These approaches have complementary properties: signatures can provide interpretable matching criteria, whereas anomaly detectors can flag patterns not represented by existing rules.

This project combines these concepts by using a twin to produce process-aware observations, an anomaly detector to gate the response, and SEM plus a rule generator to construct candidate network signatures. This paper focuses on the project architecture and implementation artifacts rather than claiming a comparison against prior systems.

## III. System Architecture

### A. End-to-End Data Flow

The target architecture places a network boundary (pfSense with Snort IPS) between an external client and the digital twin. Modbus TCP requests are handled by the twin, which updates virtual state through a state manager and physics engine. The twin emits structured telemetry containing network fields, process and actuator values, previous state, state changes, and derived network statistics.

Telemetry is consumed in parallel by the anomaly detector and SEM. SEM produces a candidate behavioral signature, and the rule generator converts it to a candidate Snort rule. The decision engine waits for anomaly detection: when the result is normal, the candidate signature and rule are discarded; when anomalous, the candidate can be selected for enforcement. The target architecture places the enforcement action at Snort IPS on pfSense. This design also specifies that attacker commands must never be propagated to the real Stage 1; synchronization with the physical stage is read-only.

### B. Digital Twin and Process Isolation

The digital twin includes a state manager and deterministic physics engine. The state manager owns the current and previous virtual state, timestamps, and version metadata. The physics engine represents process relationships, including flow, levels, pumps, valves, sensors, and physical bounds. A Modbus command changes virtual actuator state, and the engine computes the resulting virtual process response. Thus, a client can receive a plausible SCADA response while the real plant remains isolated from untrusted control traffic.

### C. Telemetry and Feature Contract

The documented detector contract contains 20 features: AIT504.Pv, bytes_per_sec, PIT501.Pv, AIT303.Pv, unique_dst_ips, PIT503.Pv, DPIT301.Pv, P1_STATE, AIT503.Pv, unique_src_ips, bytes_per_packet, max_packet_size, packet_size_range, avg_packet_size, packets_per_sec, packet_count, total_bytes, AIT502.Pv, small_packets_count, and unique_ip_pairs. These combine process measurements with network rates, counts, and address diversity. A fixed feature order is essential because the trained scaler and detector expect the same input schema.

### D. Detection and Response Components

The training script fits a StandardScaler to normal-labeled training rows and trains an Isolation Forest and novelty-mode Local Outlier Factor (LOF). It stores the scaled normal mean and standard deviation for a third, z-score-based component. The packaged model uses weights of 0.25, 0.25, and 0.50 for Isolation Forest, LOF, and z-score, respectively, with a configurable threshold initialized to 0.15. The runtime detector combines normalized component scores to produce an anomaly decision and score.

SEM extracts a candidate signature from observed behavior, and a rule generator turns that signature into a candidate Snort rule. The decision engine implements the gating contract: an anomaly yields BLOCK and retains the candidate signature/rule; a normal result yields ALLOW and discards both. The repository further includes a separate firewall manager and orchestrator capable of applying IP/port rules in database or iptables modes. The exact correspondence between that general firewall path and the target pfSense/Snort path should be established in deployment-specific integration testing.

## IV. Implementation

The project is implemented primarily in Python. The repository includes modules for telemetry, feature extraction, real-time anomaly detection, orchestration, firewall management, packet capture or simulated traffic, decision logic, rule generation, and digital-twin physics/state management. The training script reads a labeled CSV dataset, selects rows with `y_true == 0` for the normal baseline, fills missing feature values with zero, fits the scaler, trains the ensemble, and serializes the model using Python pickle.

The training code uses a fixed random seed for the Isolation Forest. LOF is configured with 30 neighbors and novelty detection. The z-score component uses the maximum absolute standardized feature deviation, scaled by 3 and clipped to the range [0, 1]. The ensemble combines the normalized Isolation Forest and LOF scores with the z-score component. Since the implementation normalizes some component scores relative to the current evaluated batch, score behavior may depend on batch composition; this is an important consideration for online inference and should be resolved or characterized through evaluation.

The architecture documentation defines a Snort/pfSense deployment goal, while the integration guide describes a standalone firewall manager and packet processing demo. Accordingly, this draft characterizes the repository as a prototype with multiple enforcement integration paths, rather than asserting that every documented target deployment has been exercised end-to-end.

## V. Evaluation and Reported Results

### A. Project-Reported Metrics

Project integration documentation reports 95.65% recall, 82.37% precision, and 78.03% weighted accuracy for the anomaly detection system. It also reports approximately 5–10 ms inference per sample and a 5–10 s window-based detection latency. These figures are included as reported project metrics, not as independently verified experimental findings. The inspected documentation does not provide a complete confusion matrix, class-wise support, dataset version/split details sufficient to reproduce the reported values, or repeated-run uncertainty estimates. The training script includes validation functionality, but its `validate_model` procedure samples the first rows and does not calculate these classification metrics.

### B. Digital Twin Assessment Evidence

A project assessment report describes simulated multi-stage attack scenarios and reports that register changes were logged and the simulation remained stable during a run exceeding 20 s. It also lists limitations, including simplified pressure behavior and limited displayed evidence for chemistry sensors. These observations are useful as functional evidence for the twin, but the report does not provide a controlled benchmark protocol or raw logs in the material used for this draft; therefore, they are not treated as a formal quantitative evaluation.

### C. Required Reproducible Evaluation

A rigorous evaluation should identify the exact dataset and label mapping, publish the temporal train/validation/test boundaries, and report the number of samples in each class. The held-out test set should be evaluated with a fixed detector threshold and metrics including confusion matrix, precision, recall, F1-score, false-positive rate, and ROC-AUC or precision-recall AUC where appropriate. Results should be reported per attack class and across multiple seeds or temporal folds. System measurements should separately report feature-window duration, event-to-decision latency, rule-generation/deployment latency, memory use, and throughput on specified hardware. End-to-end tests should verify that normal events discard candidate rules, anomalous events activate rules, and no attacker-originated write reaches the physical Stage 1.

## VI. Discussion

The main design strength is the separation of observation, simulation, detection, decision, and enforcement. The digital twin supplies process context without requiring the live plant to absorb untrusted commands. The anomaly-gated rule flow also avoids activating a candidate rule solely because SEM observed a pattern; the decision engine requires an anomaly result. The fixed feature contract and modular components support repeatable integration when their interfaces are kept aligned.

Several implementation and evidence issues remain. First, reported detector metrics need an explicit and reproducible held-out evaluation. Second, score normalization relative to an inference batch can make scores shift as batch composition changes; online scoring should use calibration constants established from training data or another documented fixed mapping. Third, the target Snort/pfSense workflow and the standalone firewall manager should be verified as one deployment path, including rule syntax validation, activation, rollback, and packet blocking. Fourth, feature mappings from digital-twin telemetry to the detector’s 20-column schema must be fully documented and tested. Finally, the physical isolation invariant should be validated at the network and application layers, not inferred from architecture documentation alone.

## VII. Conclusion

This paper presented an integrated SCADA security prototype built around an isolated digital twin honeypot, mixed process/network telemetry, ensemble anomaly detection, candidate signature and rule generation, and anomaly-gated enforcement. The design aims to combine cyber and process evidence while ensuring that untrusted control requests affect only virtual state. Repository artifacts implement key pipeline components and document a target Snort/pfSense deployment, alongside a distinct firewall-management integration path. Project materials report promising detector metrics, but their experimental provenance is insufficient for independent reproduction from the inspected artifacts. Future work should complete end-to-end deployment validation, fix or characterize inference score calibration, publish reproducible held-out results, and test the physical isolation and enforcement properties under controlled attack scenarios.

## References

[1] Project repository, “System Architecture,” `docs/architecture.md`, accessed Nov. 23, 2026.

[2] Project repository, “System Requirements,” `docs/requirements.md`, accessed Nov. 23, 2026.

[3] Project repository, “Telemetry Schema,” `docs/telemetry-schema.md`, accessed Nov. 23, 2026.

[4] Project repository, “Train and Save Anomaly Detection Models,” `train_models.py`, accessed Nov. 23, 2026.

[5] Project repository, “Anomaly-Gated Enforcement Decision Contract,” `decision_engine.py`, accessed Nov. 23, 2026.

[6] Project repository, “Integration Summary,” `README_INTEGRATION.md`, accessed Nov. 23, 2026.

[7] Project repository, “Digital Twin Assessment Report,” `Digital Twin/DT_ASSESSMENT_REPORT.md`, accessed Nov. 23, 2026.

## Author Notes Before Submission

- Replace author and institution placeholders.
- Add the exact dataset citation, version, license, sample counts, and train/test boundaries.
- Recompute and include the confusion matrix and all claimed metrics from a held-out test split.
- Confirm whether reported performance refers to the detector model, the complete pipeline, or a specific experiment.
- Add deployment hardware/software versions and measured end-to-end Snort/pfSense results.
- Apply the target conference or journal's IEEE template; this Markdown draft follows IEEE sectioning and terminology but is not yet a two-column IEEEtran manuscript.

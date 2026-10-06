# Project Memory

## Project

This is a university capstone focused on:

- SCADA security
- Digital Twins
- Industrial IoT
- anomaly detection
- attack signature extraction
- automated IPS response

---

# Current Repository

The existing repository contains research/prototype implementations for:

- Digital Twin
- Physics Engine
- Mistral/Ollama engine
- Anomaly Detection
- Signature Extraction Module

Much of the existing code is experimental and may require refactoring.

Do not assume existing structure is the final architecture.

---

# Important Existing Work

The anomaly detection model has already been trained/evaluated.

The current optimized model uses 20 features combining:

- 7 sensor features
- 13 network features

Preserve this work unless a deliberate redesign is approved.

---

# Design Decisions

## Decision 1

Digital Twin is inline and acts as a honeypot.

## Decision 2

Attacker traffic can modify the simulated DT but never the real physical Stage 1.

## Decision 3

Physical Stage 1 periodically provides read-only reference state to the DT.

## Decision 4

Physics Engine is the deterministic physical model.

## Decision 5

Mistral is a hybrid simulation/realism engine.

## Decision 6

Physics Engine is the fallback when Ollama/Mistral is unavailable.

## Decision 7

Mistral output must be physically validated.

## Decision 8

Telemetry contains both network and process information.

## Decision 9

Anomaly Detection and SEM run in parallel.

## Decision 10

SEM produces a candidate signature.

## Decision 11

Rule Generator produces a candidate Snort rule.

## Decision 12

The system waits for Anomaly Detection before enforcement.

## Decision 13

Normal → discard candidate rule and permit traffic.

## Decision 14

Anomaly → activate rule and block traffic.

## Decision 15

The packet that caused an anomaly must never reach Main SCADA.

## Decision 16

Latency optimization is not a Phase-1 priority.

---

# Deployment

Kali:
    attacker

Debian:
    DT + AD + SEM + Mistral

pfSense:
    firewall + Snort IPS

---

# Current Priority

Correct integration > optimization.

Do not prematurely optimize latency.

Do not introduce agentic architectures unless explicitly requested.

Do not replace working ML research with a new model without discussion.

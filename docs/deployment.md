# Deployment Architecture

## Virtual Machines

### Kali VM

Role:

    Attacker

Contains:

    - attack scripts
    - Modbus clients
    - network/security testing tools

Kali must not run project detection components.

---

### Debian VM

Role:

    Main application environment

Contains:

    - Digital Twin
    - Modbus server
    - State Manager
    - Physics Engine
    - Mistral/Ollama
    - Telemetry
    - Anomaly Detection
    - SEM
    - Rule Generator
    - Decision Engine

---

### pfSense VM

Role:

    Network firewall and IPS

Contains:

    - firewall
    - routing
    - Snort IPS

pfSense is managed/accessed through its web interface from Debian where required.

---

# Network Topology

Kali
  |
  | attacker traffic
  v
pfSense
  |
  v
Debian Digital Twin
  |
  | permitted traffic
  v
Main SCADA

Physical Stage 1
  |
  | periodic read-only state synchronization
  v
Debian Digital Twin

---

# Security Rules

Kali must never have a direct route to:

- Physical Stage 1
- Main SCADA

Attacker traffic must pass through the Digital Twin/security boundary.

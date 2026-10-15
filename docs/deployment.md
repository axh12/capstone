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

### Ubuntu VM

Role:

    Main application environment

Contains:

    - Digital Twin
    - Modbus server
    - State Manager
    - Physics Engine
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

pfSense is managed/accessed through its web interface from Ubuntu where required.

---

# Network Topology

Kali
  |
  | attacker traffic
  v
pfSense
  |
  v
Ubuntu Digital Twin
  |
  | permitted traffic
  v
Main SCADA

Physical Stage 1
  |
  | periodic read-only state synchronization
  v
Ubuntu Digital Twin

---

# Security Rules

Kali must never have a direct route to:

- Physical Stage 1
- Main SCADA

Attacker traffic must pass through the Digital Twin/security boundary.

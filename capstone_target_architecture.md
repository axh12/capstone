# Capstone --- Target Architecture & VirtualBox Configuration Specification

## 1. Purpose

This document defines the target architecture for the capstone ICS/SCADA
security system and the VirtualBox networking configuration required to
support it.

The implementation goal is:

> An external client interacts with an inline SCADA Digital Twin
> honeypot. Modbus commands are executed against the virtual plant,
> producing realistic process-state changes. The resulting mixed
> network + process telemetry is sent in parallel to Anomaly Detection
> and the Signature Extraction Module (SEM). SEM generates a candidate
> signature and the Rule Generator produces a candidate IPS rule. The
> system waits for Anomaly Detection to finish. If anomalous, the rule
> is pushed to Snort IPS/pfSense and the traffic is dropped at the
> inline security boundary; the real physical Stage 1 never receives the
> malicious packet. If not anomalous, the candidate rule is discarded
> and the packet is forwarded to the real Stage 1.

Latency optimization is explicitly deferred. Correctness, isolation,
determinism, observability, and safety take priority.

------------------------------------------------------------------------

## 2. Current Host / VirtualBox State

Current host:

-   Physical NIC: `enp3s0`
-   Host IP: `10.2.22.52/24`
-   Default gateway: `10.2.22.1`
-   VirtualBox: `6.1.50_Ubuntu r161033`

Current VirtualBox networks:

-   `vboxnet0`: `192.168.56.0/24`, DHCP disabled, currently DOWN
-   `vboxnet2`: `192.168.58.0/24`, DHCP disabled, currently UP

Current VM inventory:

### pfSense

-   State: saved/off
-   NIC 1: `vboxnet0`
-   NIC 2: `vboxnet2`

### Ubuntu (Digital Twin & Telemetry Host)

-   State: target / pending import
-   NIC 1: NAT
-   NIC 2: `vboxnet1`

### Kali

-   State: aborted/off
-   NIC 1: `vboxnet0`

### Current topology problem

Previously Kali and Debian shared `vboxnet2` directly:

``` text
Kali --------+
             |
Debian ------+---- vboxnet2 (192.168.58.0/24)
             |
pfSense -----+
```

This was replaced with isolated host-only zones where Kali accesses pfSense via `vboxnet0`, and pfSense connects to Ubuntu via `vboxnet1`.

Do not preserve this as the final production/lab data path.

------------------------------------------------------------------------

# 3. Target Security Architecture

The target logical architecture is:

``` text
                         EXTERNAL CLIENT / ATTACKER
                                  |
                                  | Modbus TCP
                                  v
                         +--------------------+
                         |      pfSense       |
                         |    Snort IPS       |
                         | Network boundary   |
                         +---------+----------+
                                   |
                            Honeypot Network
                                   |
                                   v
                    +--------------------------+
                    |    DIGITAL TWIN          |
                    |       HONEYPOT           |
                    |                          |
                    |  Modbus Gateway          |
                    |       |                  |
                    |       v                  |
                    |  State Manager           |
                    |       |                  |
                    |       v                  |
                    |  Physics Engine          |
                    |       |                  |
                    |       v                  |
                    |  Mistral/Ollama Engine   |
                    |       |                  |
                    |       v                  |
                    |  State Validation        |
                    +------------+-------------+
                                 |
                          Mixed Telemetry
                                 |
                 +---------------+----------------+
                 |                                |
                 v                                v
        +-------------------+            +-------------------+
        | Anomaly Detection |            |       SEM         |
        | Sensor + Network  |            | Candidate         |
        | features          |            | Signature         |
        +---------+---------+            +---------+---------+
                  |                                |
                  |                         Rule Generator
                  |                                |
                  |                         Candidate Rule
                  |                                |
                  +---------------+----------------+
                                  |
                         WAIT FOR ANOMALY DETECTION
                                  |
                                  v
                         +------------------+
                         | Decision Engine  |
                         +--------+---------+
                                  |
                       +----------+----------+
                       |                     |
                    NORMAL                 ANOMALY
                       |                     |
                       v                     v
                Discard candidate       Push rule to
                    rule                 Snort IPS
                       |                     |
                       v                     v
                  Forward to              DROP
                  real Stage 1
```

Important: pfSense/Snort and the DT have different responsibilities.

-   pfSense/Snort provides network enforcement.
-   The DT is the deception/simulation environment.
-   The DT must not expose the physical Stage 1 to attacker commands.
-   A malicious packet is first processed inside the DT/honeypot, not
    the real plant.
-   The real Stage 1 only receives traffic after the security decision
    permits forwarding.

------------------------------------------------------------------------

# 4. Network Zones

The final VirtualBox design should provide separate security zones.

## Zone A --- Attacker / External Client

Contains:

-   Kali
-   Other test clients if needed

Purpose:

-   Generate Modbus TCP traffic
-   Simulate legitimate clients and attackers

Kali must NOT share an unrestricted L2 segment with the DT.

------------------------------------------------------------------------

## Zone B --- pfSense WAN / Untrusted Side

This is the interface through which the attacker reaches the security
boundary.

------------------------------------------------------------------------

## Zone C --- Honeypot / DT Network

Contains:

-   Digital Twin
-   Any DT-side services required for Modbus
-   Detection telemetry interfaces as appropriate

This is where attacker packets are accepted by the honeypot.

------------------------------------------------------------------------

## Zone D --- Real SCADA / Stage 1 Network

Contains:

-   Physical Stage 1
-   Any required real SCADA/PLC/engineering endpoints

This zone must not be directly reachable from the attacker network.

The exact IP/subnet of the physical Stage 1 MUST be discovered before
configuring this zone.

Do not invent or overwrite the Stage 1 IP configuration.

------------------------------------------------------------------------

# 5. Important Networking Requirement

The physical Stage 1 currently has not been fully mapped in the
VirtualBox discovery.

The host is on:

``` text
10.2.22.0/24
Host: 10.2.22.52
Gateway: 10.2.22.1
```

This does NOT prove that Stage 1 is on the same subnet.

Before modifying networking, identify:

-   Stage 1 IP address
-   Stage 1 subnet
-   Stage 1 gateway, if any
-   Which physical interface/VLAN/switch carries Stage 1 traffic
-   Whether the host's `enp3s0` is directly connected to the Stage 1
    network or a general-purpose LAN

Codex MUST NOT assume that `10.2.22.0/24` is the Stage 1 network.

------------------------------------------------------------------------

# 6. Digital Twin Responsibilities

The Digital Twin is an inline SCADA honeypot.

It must:

1.  Accept Modbus TCP client traffic.
2.  Parse and validate Modbus requests.
3.  Maintain a virtual Stage-1 process state.
4.  Apply attacker/operator commands to the virtual state.
5.  Simulate physical consequences.
6.  Return believable Modbus responses.
7.  Generate process + network telemetry.
8.  Keep the physical Stage 1 isolated from attacker commands.
9.  Hold the relevant traffic until the security decision is complete.
10. Forward only traffic explicitly permitted by the security decision.

The DT is not merely a packet logger.

Example:

``` text
Client:
Write inlet valve = OPEN

DT:
  actuator changes
       |
       v
Physics:
  inflow increases
       |
       v
Mistral:
  models coupled state evolution,
  delays, interactions and realistic variation
       |
       v
Sensor:
  tank level increases realistically
```

The attacker should see a believable SCADA response.

------------------------------------------------------------------------

# 7. Digital Twin Internal Architecture

``` text
                 Modbus TCP Request
                        |
                        v
                +---------------+
                | Modbus Gateway|
                +-------+-------+
                        |
                        v
                +---------------+
                | State Manager |
                +-------+-------+
                        |
                        v
                +---------------+
                | Physics Engine|
                +-------+-------+
                        |
                        v
                +---------------+
                | Mistral/Ollama|
                | Engine        |
                +-------+-------+
                        |
                        v
                +---------------+
                | State         |
                | Validator     |
                +-------+-------+
                        |
                        v
                 Simulated State
```

------------------------------------------------------------------------

# 8. State Manager

The State Manager is the single source of truth for the current Digital
Twin state.

It is NOT:

-   the physics engine
-   the LLM
-   the anomaly detector
-   the security decision engine

It maintains:

-   current sensor values
-   current actuator states
-   previous state
-   state timestamp
-   state version
-   active/pending commands
-   last synchronization time with physical Stage 1
-   synchronization metadata
-   current simulation mode

The State Manager provides the state to:

-   Physics Engine
-   Mistral Engine
-   Modbus response layer
-   telemetry generator
-   Stage-1 synchronization logic

All components should obtain the authoritative virtual state through the
State Manager rather than maintaining independent copies.

------------------------------------------------------------------------

# 9. Physical Stage 1 Synchronization

The Digital Twin must periodically pull/read state from the physical
Stage 1.

Direction:

``` text
Physical Stage 1
       |
       | READ / TELEMETRY ONLY
       v
State Manager
       |
       v
Digital Twin baseline
```

Attacker traffic must NEVER be propagated from the DT into the physical
Stage 1 as a control action.

The physical Stage 1 is a reference source for the twin.

Synchronization should update/reconcile the virtual baseline without
allowing physical plant commands to originate from the attacker.

The exact synchronization interval is configurable and should be made an
environment variable/configuration value.

Suggested initial configuration:

``` text
STAGE1_SYNC_INTERVAL_SECONDS=<configurable>
```

Do not hard-code a value until the Stage 1 communication characteristics
are known.

------------------------------------------------------------------------

# 10. Hybrid Physics + Mistral Engine

The project will use a hybrid model.

## Physics Engine

The Physics Engine provides:

-   deterministic baseline plant behaviour
-   physical constraints
-   actuator-to-process relationships
-   conservation/flow relationships
-   safe bounds
-   fallback behaviour

The Physics Engine is the mandatory fallback when Ollama/Mistral is
unavailable.

## Mistral Engine

Mistral is used to improve simulation of complex coupled state changes
and realistic behaviour.

Examples:

-   simultaneous inlet and outlet changes
-   interacting pumps/valves
-   delayed process response
-   coupled sensor behaviour
-   complex operating transitions
-   realistic temporal variation

Mistral should NOT be allowed to produce unrestricted arbitrary plant
states.

Conceptually:

``` text
Current State
     +
Incoming Commands
     +
Recent State History
     +
Physics Constraints
     |
     v
 Mistral/Ollama
     |
     v
Candidate State
     |
     v
State Validator
     |
     v
Final DT State
```

If Ollama is unavailable, times out, or returns unusable data:

``` text
Mistral unavailable
       |
       v
Physics Engine
       |
       v
Validated State
```

The DT must continue operating.

------------------------------------------------------------------------

# 11. Mistral Output Contract

The exact model prompt/schema should be implemented as a strict
structured interface.

Mistral should preferably return state transitions/deltas or a
constrained next-state representation rather than unrestricted prose.

Conceptually:

``` json
{
  "state_version": 123,
  "next_state": {
    "LIT101": 523.7,
    "FIT101": 2.48,
    "P101": 1,
    "MV101": 1
  },
  "confidence": 0.91,
  "reason": "coupled inlet/outlet transition"
}
```

The actual schema must match the existing project model and register
map.

Never trust the LLM output directly.

The validator must enforce:

-   numeric type validity
-   register/state validity
-   sensor bounds
-   actuator validity
-   physically impossible transitions
-   required fields
-   stale/out-of-order state handling

If validation fails, use the Physics Engine fallback.

------------------------------------------------------------------------

# 12. Telemetry

The DT must emit a structured telemetry event whenever a meaningful
request/state transition occurs.

Telemetry contains both:

1.  Network telemetry
2.  Process/sensor telemetry

This is important because the trained anomaly model uses mixed sensor
and network inputs.

## Network telemetry

Include fields required by the existing model and feature-engineering
pipeline, such as:

-   timestamp
-   source IP
-   destination IP
-   source port
-   destination port
-   protocol
-   Modbus function code
-   register/address where applicable
-   requested value where applicable
-   packet count
-   total bytes
-   unique source IP count
-   unique destination IP count
-   traffic/byte rate features

The exact field names MUST be aligned with the existing
anomaly-detection schema in the repository.

## Process telemetry

Include the relevant Stage-1/Digital-Twin process variables:

-   sensor values
-   actuator states
-   valve states
-   pump states
-   flow values
-   level values
-   other variables used by the existing model

Again, use the repository's canonical feature names rather than
inventing duplicate names.

## Derived process telemetry

Where required by the model, calculate:

-   delta from previous value
-   rate of change
-   rolling statistics
-   actuator transitions
-   temporal features

Feature engineering should happen in a dedicated detection/normalization
layer, not be duplicated across the DT.

------------------------------------------------------------------------

# 13. Telemetry Event Example

Conceptual structure:

``` json
{
  "event_id": "uuid",
  "timestamp": "ISO-8601",
  "session_id": "uuid",

  "network": {
    "src_ip": "x.x.x.x",
    "dst_ip": "x.x.x.x",
    "src_port": 12345,
    "dst_port": 502,
    "protocol": "modbus_tcp",
    "function_code": 6,
    "register": 20,
    "value": 1,
    "packet_count": 1,
    "total_bytes": 64
  },

  "process": {
    "LIT101": 523.7,
    "FIT101": 2.48,
    "P101": 1,
    "MV101": 1
  },

  "changes": {
    "LIT101_delta": 0.4,
    "FIT101_delta": 2.48,
    "P101_changed": true,
    "MV101_changed": true
  }
}
```

This is illustrative. The production schema must use the existing
repository's model feature names and expected types.

------------------------------------------------------------------------

# 14. Anomaly Detection

The anomaly detector receives the normalized telemetry generated by the
DT.

The existing model uses mixed sensor/process and network features.

The pipeline is:

``` text
DT Telemetry
     |
     v
Feature Normalization
     |
     v
Model Feature Vector
     |
     v
Anomaly Detection
     |
     v
Anomaly Score / Decision
```

The detector should return structured output such as:

``` json
{
  "event_id": "uuid",
  "is_anomaly": true,
  "score": 0.94,
  "detectors": {
    "isolation_forest": true,
    "lof": true,
    "z_score": true
  }
}
```

The exact score semantics must match the existing implementation.

------------------------------------------------------------------------

# 15. SEM

SEM runs in parallel with Anomaly Detection.

SEM should not wait for Anomaly Detection.

Flow:

``` text
Telemetry
    |
    v
   SEM
    |
    v
Candidate Signature
```

The SEM output is initially a CANDIDATE signature because anomaly
detection has not yet confirmed malicious/anomalous behaviour.

A candidate signature may describe:

-   protocol
-   source/destination characteristics
-   Modbus function
-   target register
-   value pattern
-   frequency
-   packet characteristics
-   process impact
-   temporal characteristics

The existing signature extraction implementation should be
reused/extended rather than replaced without reason.

------------------------------------------------------------------------

# 16. Rule Generator

The Rule Generator consumes the candidate SEM signature.

Flow:

``` text
Candidate Signature
       |
       v
Rule Generator
       |
       v
Candidate Snort Rule
```

SEM should not directly generate raw Snort syntax.

Responsibilities:

-   translate normalized signature into an enforcement rule
-   validate rule structure
-   prevent unsafe/broader-than-intended rules
-   assign rule ID/version
-   record the source event/signature
-   support rule lifecycle management

The generated rule is a candidate until Anomaly Detection confirms the
event.

------------------------------------------------------------------------

# 17. Decision / Correlation Stage

For the initial implementation, the decision logic is intentionally
simple:

``` text
SEM + Rule Generator
          |
          | candidate rule
          v
      WAIT FOR AD
          |
          v
   Anomaly Detection
          |
      +---+---+
      |       |
   NORMAL   ANOMALY
      |       |
      v       v
   DISCARD   PUSH IPS
```

The system MUST wait for Anomaly Detection to finish before pushing the
candidate rule to Snort IPS.

Do not add complicated risk scoring or autonomous policy logic unless
explicitly required later.

Future enhancement can combine:

-   anomaly score
-   SEM confidence
-   process impact
-   source reputation
-   asset criticality
-   repeated activity

But that is outside the initial architecture.

------------------------------------------------------------------------

# 18. Inline Packet Lifecycle

This is critical.

The system is inline.

The packet that triggers an anomaly must NOT reach the real Stage 1.

The conceptual lifecycle is:

``` text
Packet arrives
      |
      v
Digital Twin
      |
      v
Execute/simulate in honeypot
      |
      v
Generate telemetry
      |
      +--------------------+
      |                    |
      v                    v
Anomaly Detection        SEM
      |                    |
      |                    v
      |              Rule Generator
      |                    |
      |              Candidate Rule
      |                    |
      +---------+----------+
                |
         WAIT FOR AD
                |
         +------+------+
         |             |
      NORMAL        ANOMALY
         |             |
         v             v
      Forward      Push rule
      to Stage 1      to IPS
                       |
                       v
                      DROP
```

The attacker can observe the simulated effect inside the DT.

The physical Stage 1 cannot observe the malicious command.

------------------------------------------------------------------------

# 19. Important Distinction: First Malicious Packet vs Subsequent Packets

The first packet that causes the anomaly is processed by the DT.

Once the system confirms the anomaly and pushes the generated rule:

``` text
Subsequent matching packets
        |
        v
   Snort/pfSense
        |
        v
       DROP
```

The rule therefore provides persistent enforcement against subsequent
matching traffic.

Do not design the system around retroactively sending the
already-processed packet backwards through the firewall.

------------------------------------------------------------------------

# 20. Connection / Forwarding Semantics

The initial implementation should prioritize correctness over latency.

Therefore, if the packet must be held while:

-   anomaly detection runs
-   SEM runs
-   rule generation runs
-   the system waits for anomaly detection

then hold the corresponding application/session decision until the
result is known.

Latency optimization is explicitly deferred.

Possible future optimizations:

-   fast-path trusted traffic
-   cached decisions
-   asynchronous rule installation
-   flow-level classification
-   batching
-   model optimization
-   precomputed safe signatures

Do not prematurely optimize the first implementation.

------------------------------------------------------------------------

# 21. Physical Stage 1 Safety

The physical Stage 1 must be treated as the protected asset.

Rules:

1.  Attacker commands terminate at the DT.
2.  DT state changes are virtual.
3.  Physical Stage 1 state is read/synchronized into the DT.
4.  Attacker-controlled DT writes must never become physical Stage 1
    writes.
5.  Forwarding to Stage 1 occurs only after the security decision
    permits it.
6.  Test attacks must target the DT, not the physical process.

------------------------------------------------------------------------

# 22. VirtualBox Target Networking

The final VirtualBox configuration should have separate networks.

A conceptual implementation is:

``` text
             ATTACKER NETWORK
                    |
                  Kali
                    |
                    v
              pfSense WAN
                    |
              pfSense IPS
                    |
                    v
              HONEYPOT NET
                    |
                    v
                   DT
                    |
              SCADA NET
                    |
                    v
             Physical Stage 1
```

VirtualBox may require:

-   one attacker-side network
-   one honeypot/DT-side network
-   one SCADA/physical-side connectivity path
-   one optional management/NAT interface

Do not assume the exact adapter type until the physical Stage 1 path is
confirmed.

------------------------------------------------------------------------

# 23. Recommended Ubuntu NIC Roles

Current Ubuntu target:

``` text
NIC1 → NAT
NIC2 → vboxnet1
```

Keep the NAT NIC as a management/development interface if required.

Do not use the NAT interface as part of the ICS security path.

The eventual DT data-plane interface(s) should belong only to the
intended security zones.

------------------------------------------------------------------------

# 24. pfSense NIC Roles

Current pfSense:

``` text
NIC1 → vboxnet0
NIC2 → vboxnet1
```

The final roles should be explicit:

``` text
WAN / attacker-side
        |
        v
     pfSense
        |
        v
DT/honeypot-side
```

If pfSense must also directly route toward the real Stage-1 network, it
may require an additional interface or a carefully designed
routing/bridge arrangement.

Do NOT add or remove interfaces until the physical Stage 1 network is
identified.

------------------------------------------------------------------------

# 25. Management Plane

Management traffic should remain separate from the ICS datapath where
practical.

Examples:

-   SSH
-   Git
-   package updates
-   Ollama model management
-   administrative APIs
-   logging/monitoring

Ubuntu's NAT interface can provide development access.

Do not accidentally expose Modbus or Stage-1 services through the
management interface.

------------------------------------------------------------------------

# 26. Logging / Observability

Every significant event should be traceable using a common `event_id`.

At minimum log:

``` text
event_id
timestamp
connection/session ID
source/destination
Modbus request
pre-state
post-state
physics result
Mistral result/fallback status
telemetry ID
anomaly result
SEM candidate signature
generated rule
IPS deployment result
forward/drop decision
```

This is important for:

-   capstone demonstration
-   debugging
-   forensic analysis
-   reproducing attacks
-   measuring detection quality

------------------------------------------------------------------------

# 27. Failure Behaviour

## Ollama/Mistral unavailable

``` text
Mistral
   X
   |
   v
Physics Engine
```

DT continues operating.

## SEM failure

The event can still proceed through Anomaly Detection, but no candidate
rule should be pushed without a valid rule artifact.

Default safe behaviour:

-   hold/deny forwarding for the affected security decision until the
    policy is explicitly defined
-   record the failure

## Anomaly Detection failure

Do not classify the traffic as normal merely because the detector
failed.

Default safe behaviour:

-   do not forward the unresolved packet to the real Stage 1
-   log the failure
-   retain the event for investigation

## Rule Generator failure

Do not push a malformed/partial rule.

The event remains unresolved and should not be treated as safe
automatically.

## Snort/pfSense deployment failure

Do not claim the attack is blocked.

Record the deployment failure and apply the configured fail-safe policy.

------------------------------------------------------------------------

# 28. Configuration Principles

All environment-specific values should be configuration-driven.

Examples:

``` text
DT_MODBUS_BIND_IP
DT_MODBUS_PORT
STAGE1_IP
STAGE1_MODBUS_PORT
STAGE1_SYNC_INTERVAL_SECONDS
OLLAMA_URL
OLLAMA_MODEL
TELEMETRY_ENDPOINT
ANOMALY_ENDPOINT
SEM_ENDPOINT
RULE_GENERATOR_ENDPOINT
PFSENSE_ENDPOINT
SNORT_RULE_PATH
```

Do not hard-code the physical Stage 1 address.

Do not hard-code VirtualBox interface names into application logic where
an environment/configuration mapping is more appropriate.

------------------------------------------------------------------------

# 29. Service Boundaries

Recommended logical services:

``` text
digital-twin
    |
    +-- modbus-gateway
    +-- state-manager
    +-- physics-engine
    +-- mistral-engine
    +-- state-validator
    +-- telemetry-publisher

detection
    |
    +-- feature-normalizer
    +-- anomaly-detector

signature
    |
    +-- sem
    +-- rule-generator

enforcement
    |
    +-- decision/correlation
    +-- snort/pfsense integration
```

These do not necessarily need to be separate VMs or containers
initially.

The boundaries are logical interfaces first.

------------------------------------------------------------------------

# 30. Recommended Event Correlation

Use a shared:

``` text
event_id
```

and, where appropriate:

``` text
session_id
flow_id
state_version
rule_id
signature_id
```

Example:

``` text
event_id
  |
  +-- telemetry event
  |
  +-- anomaly result
  |
  +-- SEM signature
  |
  +-- candidate rule
  |
  +-- IPS deployment
  |
  +-- final decision
```

This makes the entire attack traceable end-to-end.

------------------------------------------------------------------------

# 31. Initial Implementation Priority

Implement in this order:

1.  Map physical Stage 1 network.
2.  Design VirtualBox/pfSense security zones.
3.  Make DT inline between attacker side and Stage 1.
4.  Establish the canonical Stage-1 register/state map.
5.  Implement State Manager.
6.  Implement physical Stage-1 periodic synchronization.
7.  Integrate Physics Engine.
8.  Integrate Mistral/Ollama as the enhanced simulation engine.
9.  Implement strict state validation.
10. Implement mixed network + process telemetry.
11. Connect telemetry to existing Anomaly Detection.
12. Connect telemetry to SEM.
13. Connect SEM to Rule Generator.
14. Wait for Anomaly Detection before enforcement.
15. Integrate generated rules with Snort/pfSense.
16. Test normal traffic.
17. Test individual Modbus attacks.
18. Test coupled/multiple actuator changes.
19. Test Ollama failure/fallback.
20. Test detector/SEM/rule/IPS failure modes.
21. Verify that malicious traffic never reaches physical Stage 1.

------------------------------------------------------------------------

# 32. Things Codex MUST NOT Do Without Explicit Approval

Do not:

-   change the physical Stage 1 IP
-   change the physical Stage 1 configuration
-   send attacker-generated control writes to Stage 1
-   assume `10.2.22.0/24` is the Stage-1 subnet
-   destroy existing VirtualBox networks
-   delete `vboxnet0` or `vboxnet2`
-   change pfSense rules blindly
-   expose Modbus to the host LAN
-   make Mistral the sole source of physical state
-   bypass the Physics Engine validation
-   automatically forward unresolved traffic
-   push an unvalidated Snort rule
-   treat Anomaly Detection failure as a normal result
-   treat Snort deployment failure as successful blocking

------------------------------------------------------------------------

# 33. Definition of Done

The architecture is considered functionally complete when the following
demonstration works:

### Normal Modbus operation

``` text
Client
  |
  v
pfSense
  |
  v
DT
  |
  +--> simulated state change
  +--> telemetry
  |
  v
Anomaly Detection = normal
  |
  v
Candidate SEM rule discarded
  |
  v
Packet forwarded
  |
  v
Physical Stage 1
```

### Attack operation

``` text
Attacker
  |
  v
pfSense
  |
  v
DT
  |
  +--> attacker command simulated
  +--> physical consequences simulated
  +--> telemetry
       |
       +-------------------+
       |                   |
       v                   v
  Anomaly Detection       SEM
       |                   |
       |              Rule Generator
       |                   |
       |              Candidate Rule
       |                   |
       +---------+---------+
                 |
            wait for AD
                 |
                 v
            ANOMALY = TRUE
                 |
                 v
             Snort IPS
                 |
                 v
                DROP
```

The physical Stage 1 must show that it did NOT receive the malicious
command.

### Subsequent attack

``` text
Attacker
   |
   v
Snort/pfSense
   |
   v
Rule match
   |
   X
DROP
```

------------------------------------------------------------------------

# 34. Architectural Principle

The final system should be understood as a closed-loop ICS deception and
enforcement system:

``` text
ATTACK
  |
  v
DECEPTION
  |
  v
SIMULATION
  |
  v
TELEMETRY
  |
  +----------+
  |          |
  v          v
DETECTION   SIGNATURE
  |          |
  |          v
  |       RULE
  |          |
  +-----+----+
        |
        v
    ENFORCEMENT
        |
        v
     PROTECTION
```

The Digital Twin protects the real plant by allowing malicious
interaction to occur in a controlled virtual environment, while the
detection/signature pipeline converts observed behaviour into an
enforceable network rule.

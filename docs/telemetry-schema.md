# Telemetry Schema

The historical SWaT CSV and the live gateway have different feature schemas.
The 20 features below describe the historical SWaT profile. The gateway's
native profile uses 29 Twin, command and per-request network features. The
new `gateway-window` profile uses six process readings and twelve measured
60-second, per-source request statistics; see
[Research dataset workflow](research-dataset-workflow.md).
Mapped historical models can instead use five shared Stage 1 state features
or those five plus Stage 2 AIT202 pH. These state-only profiles do not use
the gateway's per-request network features.
The offline `swat-aligned` profile uses six mapped process values and twelve
CSV network aggregates from each timestamped row. The live `gateway-window`
profile uses the same feature names but separately measured per-source
request windows and must be trained from gateway sessions.
The historical CSV has aggregate network columns but no Modbus packet bytes
or register addresses, so SEM cannot extract a packet rule from one CSV row.

## Purpose

Telemetry is the contract between the Digital Twin and:

- Anomaly Detection
- SEM
- Rule Generator
- forensic logging

---

# Raw Event

Each event should contain:

event_id
timestamp

network:
    src_ip
    dst_ip
    src_port
    dst_port
    protocol
    function_code
    register
    value
    packet_size

process:
    relevant sensor values
    actuator states

previous_process:
    previous sensor values
    previous actuator states

state_change:
    relevant deltas

network_statistics:
    packet_count
    total_bytes
    bytes_per_sec
    packets_per_sec
    unique_src_ips
    unique_dst_ips
    unique_ip_pairs
    average packet size
    maximum packet size
    minimum packet size
    packet size range
    bytes per packet
    small packet count

---

# Historical top-20 SWaT Feature Contract

The historical top-20 detector expects exactly these 20 features. The
runtime detector instead reads the saved artifact's declared feature order;
the gateway checks that order against its supported profile:

AIT504.Pv
bytes_per_sec
PIT501.Pv
AIT303.Pv
unique_dst_ips
PIT503.Pv
DPIT301.Pv
P1_STATE
AIT503.Pv
unique_src_ips
bytes_per_packet
max_packet_size
packet_size_range
avg_packet_size
packets_per_sec
packet_count
total_bytes
AIT502.Pv
small_packets_count
unique_ip_pairs

Do not silently change this schema.

Any feature mapping required between the Digital Twin and this schema must be explicitly documented.

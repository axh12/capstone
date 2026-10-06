# Telemetry Schema

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

# ML Feature Contract

The current anomaly detector expects exactly these 20 features:

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

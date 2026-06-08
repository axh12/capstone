# Integration Guide: Complete Pipeline

This document explains how to use the integrated pipeline that connects the Digital Twin, Anomaly Detection, Signature Extraction, and Firewall Management systems.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Real Network / Simulation                   │
└────────────────┬────────────────────────────────────────────────┘
                 │ Packets
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Network Integration Module                      │
│  - Packet Capture (Scapy/SimulatedNetworkSource)                 │
│  - Packet buffering & statistics                                 │
└────────────────┬────────────────────────────────────────────────┘
                 │ Packet Events
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Feature Extractor                              │
│  - Extract 20 optimized sensor features                          │
│  - Extract 13 network features                                   │
│  - Build feature vectors                                         │
└────────────────┬────────────────────────────────────────────────┘
                 │ Feature Vectors
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Real-Time Anomaly Detector                          │
│  - Isolation Forest (25% weight)                                 │
│  - Local Outlier Factor (25% weight)                             │
│  - Z-Score Statistics (50% weight)                               │
└────────────────┬────────────────────────────────────────────────┘
                 │ If Anomaly Detected
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Signature Extraction (SEM)                          │
│  - Extract attack patterns from anomalous features               │
│  - Identify affected sensors & network patterns                  │
│  - Determine attack type (TRAFFIC/TAMPERING)                     │
└────────────────┬────────────────────────────────────────────────┘
                 │ Attack Signature
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Firewall Manager                                 │
│  - Generate firewall rules from signature                        │
│  - Block malicious IPs/ports                                     │
│  - Apply rules (iptables or rule database)                       │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Feature Extractor (`feature_extractor.py`)

Extracts 20 optimized features from packets and sensor data:

**Network Features (13):**
- `bytes_per_sec` - Network throughput
- `unique_dst_ips` - Number of destination IPs
- `unique_src_ips` - Number of source IPs
- `bytes_per_packet` - Average packet size
- `max_packet_size` - Largest packet
- `packet_size_range` - Variation in packet sizes
- `avg_packet_size` - Mean packet size
- `packets_per_sec` - Packet rate
- `packet_count` - Total packets
- `total_bytes` - Total data bytes
- `small_packets_count` - Packets < 64 bytes
- `unique_ip_pairs` - Unique (src, dst) combinations
- `P1_STATE` - Pump state from PLC

**Sensor Features (7):**
- `AIT504.Pv` - Analyzer input
- `PIT501.Pv` - Pressure sensor
- `AIT303.Pv` - Analyzer input
- `PIT503.Pv` - Pressure sensor
- `DPIT301.Pv` - Differential pressure
- `AIT503.Pv` - Analyzer input
- `AIT502.Pv` - Analyzer input

### 2. Real-Time Anomaly Detector (`realtime_anomaly_detector.py`)

Uses ensemble of 3 detectors:

| Detector | Weight | Purpose |
|----------|--------|---------|
| Isolation Forest | 25% | Detects rare statistical patterns |
| Local Outlier Factor | 25% | Detects density-based anomalies |
| Z-Score Statistics | 50% | Measures deviation from baseline |

**Thresholds:**
- `0.15` (default/aggressive): Catches 95%+ of attacks
- `0.35` (balanced): Good F1-score
- `0.76` (conservative): Fewer false positives

### 3. Firewall Manager (`firewall_manager.py`)

Creates and applies firewall rules:

- Block by source IP
- Block by destination IP
- Block by port
- Block by IP pair
- Temporary blocking (auto-expiration)
- Rule statistics & export

### 4. Network Integration (`network_integration.py`)

Two modes:

1. **Real Network Sniffing** (requires root):
   - Uses Scapy to capture real packets
   - Runs in background thread
   - Supports BPF filters

2. **Simulated Network** (testing):
   - Generates realistic normal/attack traffic
   - No root required
   - Perfect for testing

### 5. Integration Orchestrator (`orchestrator.py`)

Main control engine that:
- Coordinates all components
- Manages pipeline state
- Processes packet batches
- Handles anomalies
- Tracks statistics
- Exports session data

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
pip install numpy pandas scikit-learn
pip install scapy  # For real network capture (optional)
```

### 2. Train Anomaly Detection Models

First time only - trains models on historical data:

```bash
python train_models.py --data "Anomaly Detection/aligned_sensor_network_clean.csv"
```

This creates `anomaly_detection_ensemble.pkl` (~50MB)

### 3. Verify Model

```bash
python train_models.py --data "Anomaly Detection/aligned_sensor_network_clean.csv" --validate
```

## Usage Examples

### Example 1: Quick Test with Simulated Traffic

```python
from orchestrator import IntegrationOrchestrator

# Initialize with simulated network (no root required)
orchestrator = IntegrationOrchestrator(
    detector_model_path='anomaly_detection_ensemble.pkl',
    use_real_network=False,  # Simulation mode
    firewall_enabled=True,
    dry_run=True  # Don't actually apply firewall rules
)

orchestrator.start()

# Process simulated traffic
results = orchestrator.process_simulated_traffic(
    normal_count=100,
    attack_count=50,
    attack_type='exfiltration'
)

# Check results
status = orchestrator.get_pipeline_status()
print(f"Anomalies detected: {status['statistics']['anomalies_detected']}")

# Export session
orchestrator.export_session_data('session_results.json')

orchestrator.stop()
```

### Example 2: Real Network Monitoring (Linux with root)

```bash
sudo python -c "
from orchestrator import IntegrationOrchestrator
import time

orchestrator = IntegrationOrchestrator(
    detector_model_path='anomaly_detection_ensemble.pkl',
    use_real_network=True,  # Real network
    firewall_enabled=True,
    dry_run=False  # Actually apply rules!
)

orchestrator.start()

# Monitor for 5 minutes
time.sleep(300)

# Get results
status = orchestrator.get_pipeline_status()
detections = orchestrator.get_recent_detections(limit=20)

orchestrator.export_session_data('real_network_session.json')
orchestrator.stop()
"
```

### Example 3: Custom Feature Extraction

```python
from feature_extractor import FeatureExtractor
from realtime_anomaly_detector import RealTimeAnomalyDetector

# Initialize
extractor = FeatureExtractor(window_seconds=5)
detector = RealTimeAnomalyDetector('anomaly_detection_ensemble.pkl')

# Simulate packet arrival
packets = [
    {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.100', 'size': 64},
    {'src_ip': '192.168.1.2', 'dst_ip': '10.0.0.1', 'size': 512},
    # ... more packets
]

for pkt in packets:
    extractor.add_packet(pkt)

# Add sensor readings
sensor_data = {
    'AIT504.Pv': 500,
    'PIT501.Pv': 100,
    # ... other sensors
}

# Extract features and predict
feature_vector = extractor.build_feature_vector(sensor_data)
result = detector.predict(feature_vector)

print(f"Anomaly: {result.is_anomaly}")
print(f"Score: {result.ensemble_score:.3f}")
print(f"Type: {result.attack_type}")
```

### Example 4: Custom Firewall Rules

```python
from firewall_manager import FirewallManager, FirewallRule

fw = FirewallManager(use_iptables=False, dry_run=True)

# Block an IP for 5 minutes
rule_id = fw.block_ip(
    '192.168.1.50',
    reason='Exfiltration attack detected',
    duration_seconds=300
)

# Block a port
fw.block_port(502, protocol='tcp', duration_seconds=600)

# Apply rules
applied, errors = fw.apply_rules()

# Export rules
fw.export_rules('firewall_rules.json')

# Get stats
print(fw.get_rule_statistics())
```

## Configuration

### Environment Variables

```bash
# Enable verbose logging
export DEBUG=1

# Set firewall interface
export FW_INTERFACE=eth0

# Firewall mode
export FW_MODE=iptables  # or 'database'
```

### Tuning Parameters

**Anomaly Detection Threshold:**
```python
detector.set_threshold(0.35)  # Adjust sensitivity
# Lower = more sensitive (catch more attacks)
# Higher = less sensitive (fewer false positives)
```

**Feature Extraction Window:**
```python
extractor = FeatureExtractor(window_seconds=10)  # Change window size
```

**Firewall Rule Duration:**
```python
fw.block_ip(ip, duration_seconds=600)  # 10 minutes
# Remove duration for permanent blocks
```

## Output & Monitoring

### Pipeline Status

```python
status = orchestrator.get_pipeline_status()
# Returns:
# {
#   'state': 'RUNNING',
#   'uptime_seconds': 3600,
#   'statistics': {
#       'packets_processed': 50000,
#       'anomalies_detected': 12,
#       'rules_applied': 18,
#   },
#   'firewall_status': { ... }
# }
```

### Recent Detections

```python
detections = orchestrator.get_recent_detections(limit=10)
# Returns list of last 10 anomalies with:
# - timestamp
# - ensemble_score
# - attack_type ('TRAFFIC' or 'TAMPERING')
# - confidence
```

### Session Export

```json
{
  "session_start": "2024-01-15T10:30:00",
  "session_end": "2024-01-15T11:30:00",
  "pipeline_status": { ... },
  "recent_detections": [ ... ],
  "applied_rules": [ "rule_0", "rule_1", ... ]
}
```

## Integration with Digital Twin

The real-time anomaly detector feeds into the Digital Twin physics engine:

```python
from Digital_Twin.physics_engine import PhysicsEngine
from orchestrator import IntegrationOrchestrator

physics = PhysicsEngine()
orchestrator = IntegrationOrchestrator(...)

# When anomaly detected, apply to twin
for detection in orchestrator.get_recent_detections():
    if detection.is_anomaly:
        # Simulate emergency response
        actions = {
            'p101': 0,  # Stop pump
            'mv101': 1, # Open valve
            'p301': 0   # Stop process
        }
        physics.apply_actions(actions)
        state = physics.step()
        print(f"Twin simulated response: {state}")
```

## Troubleshooting

### Models won't load

```bash
# Verify model file exists
ls -la anomaly_detection_ensemble.pkl

# Re-train models
python train_models.py --validate
```

### No packets captured

Check network interface:
```bash
python -c "from network_integration import NetworkSniffer; print(NetworkSniffer().interface)"
```

### Firewall rules not applying

```python
# Check dry_run setting
fm = FirewallManager(dry_run=False)  # Disable dry run

# Verify iptables available
import subprocess
subprocess.run(['iptables', '-L'], check=True)
```

### High false positives

Lower detection sensitivity:
```python
detector.set_threshold(0.5)  # More conservative
```

## Performance Metrics

- **Inference time:** ~5-10ms per sample
- **Memory usage:** ~200MB (models + buffers)
- **Packets/sec:** 10,000+ on modern hardware
- **Detection latency:** 5-10 seconds (window-based)
- **False positive rate:** <5% with tuned threshold

## Security Notes

⚠️ **Production Deployment:**
- Run with least privilege (non-root when possible)
- Validate packet data input
- Use authenticated logging
- Regular model retraining
- Monitor false positive rates
- Backup firewall rules
- Test rules in dry-run first

## Next Steps

1. **Train models** on your real production data
2. **Test with simulated traffic** before production
3. **Monitor false positive rate** and tune threshold
4. **Integrate with SIEM** or monitoring system
5. **Add automatic alert notifications**
6. **Implement feedback loop** for model updates

## Support

For issues, check:
1. Model training completed successfully
2. Feature/model dimensions match (20 features)
3. Network interface is accessible
4. Sensor data sources are connected
5. Firewall permissions (if using iptables)

---

**Last Updated:** 2024  
**Version:** 1.0

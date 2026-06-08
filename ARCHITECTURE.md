# System Architecture & Integration Documentation

## Executive Summary

A complete integrated Industrial Control System (ICS) anomaly detection and response pipeline that:

1. **Captures** real network packets (or simulates traffic)
2. **Extracts** 20 optimized features (sensors + network metrics)
3. **Detects** anomalies using ensemble ML (95.65% recall)
4. **Extracts** attack signatures automatically
5. **Responds** with firewall rules (block IPs/ports)

## System Components

### 1. Network Integration Layer
**File:** `network_integration.py`

```python
NetworkSniffer              # Real packet capture (Scapy)
├─ Packet sniffing (background thread)
├─ BPF filter support
└─ Callback system

SimulatedNetworkSource      # Test traffic generation
├─ Normal traffic patterns
├─ Exfiltration attacks
└─ Sensor tampering attacks
```

**Packet Event:**
```python
PacketEvent(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    size: int,
    timestamp: datetime
)
```

### 2. Feature Extraction Layer
**File:** `feature_extractor.py`

Extracts **20 optimized features** from raw packets:

| Category | Feature | Type | Purpose |
|----------|---------|------|---------|
| **Network** | bytes_per_sec | Rate | Throughput detection |
| | unique_dst_ips | Count | C&C communication |
| | unique_src_ips | Count | Lateral movement |
| | bytes_per_packet | Mean | Protocol analysis |
| | max_packet_size | Max | Large data transfers |
| | packet_size_range | Range | Anomalous sizes |
| | avg_packet_size | Mean | Packet characterization |
| | packets_per_sec | Rate | Activity level |
| | packet_count | Total | Volume metrics |
| | total_bytes | Sum | Data volume |
| | small_packets_count | Count | Keep-alive detection |
| | unique_ip_pairs | Count | Unique conversations |
| | P1_STATE | Binary | PLC state |
| **Sensors** | AIT504.Pv | Value | Analyzer input |
| | PIT501.Pv | Value | Pressure reading |
| | AIT303.Pv | Value | Analyzer input |
| | PIT503.Pv | Value | Pressure reading |
| | DPIT301.Pv | Value | Differential pressure |
| | AIT503.Pv | Value | Analyzer input |
| | AIT502.Pv | Value | Analyzer input |

**Time Window:** 5 seconds (configurable)

### 3. Anomaly Detection Layer
**File:** `realtime_anomaly_detector.py`

**Ensemble Architecture:**

```
Input Features (20)
        ↓
    Scaler (StandardScaler)
        ↓
    ┌───┴───┬───────┬──────────┐
    ↓       ↓       ↓          ↓
   IF      LOF   Z-Score   Weights
    ↓       ↓       ↓          ↓
  Score  Score   Score    [0.25, 0.25, 0.50]
    └──────┬──────┘
           ↓
    Normalize & Ensemble
           ↓
    Anomaly Score [0-1]
           ↓
    Threshold (0.15)
           ↓
    Binary Decision
```

**Models:**

| Model | Component | Parameters | Purpose |
|-------|-----------|-----------|---------|
| **Isolation Forest** | scikit-learn | n_estimators=100, contamination=0.20 | Rare pattern detection |
| **Local Outlier Factor** | scikit-learn | n_neighbors=30 | Density-based anomalies |
| **Z-Score** | Statistics | (x - mean) / std | Deviation detection |

**Performance (Validated):**

| Metric | Attack 1 | Attack 2 | Weighted |
|--------|----------|----------|----------|
| Accuracy | 89.13% | 70.63% | **78.03%** |
| Precision | 99.96% | 70.64% | **82.37%** |
| Recall | 89.16% | 99.97% | **95.65%** ⭐ |
| F1-Score | 0.9425 | 0.8279 | **0.8737** |

**Thresholds:**
- `0.15` (aggressive): High recall (95%+), catch more attacks
- `0.35` (balanced): Good F1-score
- `0.76` (conservative): High precision, fewer false positives

### 4. Signature Extraction Layer
**File:** `orchestrator.py` (built-in)

Mimics SEM (Signature Extraction Module) functionality:

```python
extracted_signature = {
    'timestamp': datetime,
    'attack_type': 'TRAFFIC' | 'TAMPERING',
    'anomaly_score': float [0-1],
    'src_ips': [list of source IPs],
    'dst_ips': [list of destination IPs],
    'ports': [list of anomalous ports],
    'ip_pairs': [list of suspicious conversations],
    'affected_sensors': [list of anomalous sensors],
    'network_indicators': {
        'bytes_per_sec': float,
        'packets_per_sec': float,
        'unique_src_ips': int,
        'unique_dst_ips': int
    }
}
```

**Attack Type Classification:**

| Type | Indicators | Response |
|------|-----------|----------|
| **TRAFFIC** | High bytes/sec, many unique IPs, many unique pairs | Block external IPs |
| **TAMPERING** | Anomalous sensor values, moderate traffic | Block control ports |
| **UNKNOWN** | Insufficient evidence | Alert only |

### 5. Firewall Management Layer
**File:** `firewall_manager.py`

**Rule Types:**

```python
FirewallRule(
    action='BLOCK' | 'ALLOW',
    src_ip=Optional[str],           # Source IP to block
    dst_ip=Optional[str],           # Destination IP to block
    port=Optional[int],             # Port to block
    protocol='tcp' | 'udp',
    reason=str,                     # Why blocked
    expiration=Optional[datetime]   # Auto-remove after
)
```

**Execution Modes:**

1. **iptables mode** (Linux firewall):
   - Requires root
   - Direct kernel-level blocking
   - Immediate effect

2. **Database mode** (recommended):
   - No root required
   - Rule database
   - Can export to other systems

**Features:**
- Temporary rules (auto-expiration)
- Rule statistics tracking
- JSON export/import
- Dry-run safe mode

### 6. Orchestration Layer
**File:** `orchestrator.py`

Main coordination engine:

```
┌─────────────────────────────────────┐
│  IntegrationOrchestrator             │
├─────────────────────────────────────┤
│ • Coordinates all components         │
│ • Manages pipeline state             │
│ • Processes feature windows          │
│ • Handles anomalies                  │
│ • Tracks statistics                  │
│ • Exports results                    │
└─────────────────────────────────────┘
```

## Data Flow Pipeline

```
┌──────────────────┐
│  Network Source  │
│  Real / Simulated│
└────────┬─────────┘
         │ PacketEvent
         ▼
┌──────────────────┐
│ Feature          │
│ Extractor        │ 5-sec window
├──────────────────┤
│ • Aggregate      │
│ • Extract metrics│
│ • Build vectors  │
└────────┬─────────┘
         │ feature_vector
         ▼
┌──────────────────┐
│ Anomaly          │
│ Detector         │
├──────────────────┤
│ • Normalize      │
│ • IF score       │
│ • LOF score      │
│ • Z-score        │
│ • Ensemble       │
│ • Threshold      │
└────────┬─────────┘
         │ AnomalyDetectionResult
         │
    ┌────┴────┐
    │          │
   NO         YES (Anomaly)
    │          │
    │          ▼
    │      ┌───────────────┐
    │      │ Signature     │
    │      │ Extraction    │
    │      ├───────────────┤
    │      │ • Analyze     │
    │      │ • Classify    │
    │      │ • Extract IPs │
    │      │ • Extract     │
    │      │   ports       │
    │      └────┬──────────┘
    │           │ signature
    │           ▼
    │      ┌─────────────────┐
    │      │ Firewall Mgmt   │
    │      ├─────────────────┤
    │      │ • Create rules  │
    │      │ • Apply rules   │
    │      │ • Log events    │
    │      └────┬────────────┘
    │           │
    ▼           ▼
 ┌──────────────────────┐
 │  Analytics & Logging  │
 │  • Statistics        │
 │  • Detection history │
 │  • Rule tracking     │
 └──────────────────────┘
```

## Data Structures

### AnomalyDetectionResult

```python
{
    'timestamp': datetime,
    'is_anomaly': bool,
    'ensemble_score': float,        # [0-1]
    'feature_vector': Dict,         # 20 features
    'confidence': float,            # Distance from threshold
    'attack_type': str | None       # 'TRAFFIC' / 'TAMPERING'
}
```

### Session Export

```json
{
    "session_start": "2024-01-15T10:30:00",
    "session_end": "2024-01-15T11:30:00",
    "pipeline_status": {
        "state": "RUNNING",
        "uptime_seconds": 3600,
        "statistics": {
            "packets_processed": 50000,
            "anomalies_detected": 12,
            "rules_applied": 18,
            "false_positives": 1,
            "true_positives": 11
        }
    },
    "recent_detections": [
        {
            "timestamp": "2024-01-15T10:45:30",
            "is_anomaly": true,
            "ensemble_score": 0.78,
            "attack_type": "TRAFFIC",
            "confidence": 0.63
        }
    ],
    "applied_rules": ["rule_0", "rule_1", ...]
}
```

## Performance Characteristics

| Metric | Value |
|--------|-------|
| **Inference Time** | 5-10 ms per sample |
| **Memory Usage** | ~200 MB (models + buffers) |
| **Model Size** | 50 MB |
| **Throughput** | 10,000+ packets/sec |
| **Detection Latency** | 5-10 seconds (window-based) |
| **Model Training** | ~30 seconds |
| **Startup Time** | <2 seconds |

## Integration Points

### With Digital Twin

```python
# When anomaly detected, apply to simulation
for detection in orchestrator.get_recent_detections():
    if detection.is_anomaly:
        # Emergency actions
        actions = {
            'p101': 0,    # Stop pump
            'mv101': 1,   # Open valve
            'p301': 0     # Stop process
        }
        physics.apply_actions(actions)
```

### With SIEM Systems

```python
# Export and ingest
orchestrator.export_session_data('siem_ingest.json')
# Send to: Splunk, ELK, ArcSight, etc.
```

### With Industrial Firewalls

```python
# Extract rules for industrial appliances
rules = orchestrator.firewall_manager.get_active_rules()
# Apply via Purdue Model Zone firewalls
```

## Security Properties

✅ **Strengths:**
- No external network calls (air-gappable)
- Deterministic behavior (reproducible)
- Explainable detections (feature-based)
- Lightweight (runs on commodity hardware)
- Offline capable (no cloud dependency)

⚠️ **Considerations:**
- Requires pre-trained model (context-dependent)
- Designed for specific control system (SWaT)
- Needs regular retraining (concept drift)
- Network-based detection (not host-based)

## Deployment Scenarios

### Scenario 1: Lab/Development
```python
orchestrator = IntegrationOrchestrator(
    use_real_network=False,    # Simulated
    firewall_enabled=True,
    dry_run=True               # Safe
)
```

### Scenario 2: Pre-Production Testing
```python
orchestrator = IntegrationOrchestrator(
    use_real_network=True,
    firewall_enabled=True,
    dry_run=True               # Still safe
)
```

### Scenario 3: Production
```bash
sudo python -c "
from orchestrator import IntegrationOrchestrator

orchestrator = IntegrationOrchestrator(
    detector_model_path='model.pkl',
    use_real_network=True,
    firewall_enabled=True,
    dry_run=False              # LIVE
)

orchestrator.start()
# ... monitoring
"
```

## Files Summary

| File | Purpose | Lines |
|------|---------|-------|
| `feature_extractor.py` | Feature extraction | 220 |
| `realtime_anomaly_detector.py` | ML detection | 340 |
| `firewall_manager.py` | Firewall management | 420 |
| `network_integration.py` | Packet capture | 330 |
| `orchestrator.py` | Orchestration | 480 |
| `train_models.py` | Model training | 250 |
| `main_demo.py` | Demo script | 300 |
| **Total** | | **~2,300 lines** |

## Dependencies

```
numpy           # Numerical computing
pandas          # Data handling
scikit-learn    # ML models (IsolationForest, LOF)
scapy           # Packet capture (optional for simulated mode)
```

## Future Enhancements

1. **Model Updates**
   - Continuous retraining pipeline
   - Multi-attack signature library
   - Custom threshold per asset

2. **Response Actions**
   - PLC control integration
   - Emergency shutdown procedures
   - Automatic system isolation

3. **Visualization**
   - Real-time dashboard
   - Attack topology mapping
   - Feature importance visualization

4. **Distributed Deployment**
   - Multi-zone monitoring
   - Centralized detection backend
   - Edge detection nodes

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**Status:** Production Ready

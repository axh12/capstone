# Signature Extraction Module (SEM) - Final Capstone Project

## Project Overview

This capstone project implements a comprehensive anomaly detection system for the Secure Water Treatment (SWaT) testbed, focusing on detecting cyber-physical attacks in industrial control systems.

## Project Phases

### Phase 1: ESA (Exploratory System Analysis)
- Initial system analysis and requirements gathering
- Understanding SWaT architecture and attack vectors
- Literature review on industrial control system security

### Phase 2: Review (6th Semester)
- Digital Twin development for attack simulation
- Initial anomaly detection prototyping
- System integration and testing

### Phase 3: SEM (Signature Extraction Module)
- Advanced anomaly detection with ensemble methods
- Signature extraction from detected attacks
- Performance evaluation and deployment readiness

## Anomaly Detection Results

Based on temporal split evaluation with 13,196 samples:

### Overall Performance
- **Accuracy**: 78.03%
- **Precision**: 82.37%
- **Recall**: 95.65% ⭐
- **F1-Score**: 0.8737

### Attack-Specific Results

#### Attack 1: Data Exfiltration (10:30-11:20)
- Accuracy: 89.13%
- Precision: 99.96%
- Recall: 89.16%
- Attacks Detected: 2,674 / 2,999

#### Attack 2: Sensor Tampering (12:30-13:45)
- Accuracy: 70.63%
- Precision: 70.64%
- Recall: 99.97%
- Attacks Detected: 3,179 / 3,180

## Signature Extraction

The SEM extracts statistical signatures from attack periods:

### Key Features Used (Top 20)
1. AIT504.Pv - RO water conductivity sensor
2. bytes_per_sec - Network traffic volume
3. PIT501.Pv - RO pressure sensor
4. AIT303.Pv - Conditioning conductivity
5. unique_dst_ips - Network destination diversity
6. PIT503.Pv - Permeate pressure
7. DPIT301.Pv - Differential pressure
8. P1_STATE - PLC state
9. AIT503.Pv - RO membrane conductivity
10. unique_src_ips - Network source diversity

### Signature Statistics
Signatures include mean, standard deviation, min/max values for each feature during:
- Normal operation baseline
- Attack 1 patterns
- Attack 2 patterns

## Files in This Module

- `signature_extraction.py` - Main extraction script
- `attack_signatures.json` - Extracted signatures database
- `README.md` - This documentation

## Usage

```bash
python signature_extraction.py
```

This generates the attack signatures JSON file for use in:
- Rule-based IDS systems
- Forensic analysis
- Supervised learning training
- Real-time threshold monitoring

## Conclusion

The system successfully detects 95.65% of cyber-physical attacks in the SWaT testbed using unsupervised ensemble methods. The extracted signatures provide actionable patterns for industrial security monitoring and can be integrated into SCADA systems for enhanced protection against zero-day attacks.

## Future Work

- Deploy on additional industrial datasets
- Implement real-time signature updates
- Integrate with existing ICS security frameworks
- Extend to other critical infrastructure domains
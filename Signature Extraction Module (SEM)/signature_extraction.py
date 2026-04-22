"""
Signature Extraction Module (SEM)
==================================

This module extracts attack signatures from the SWaT anomaly detection outputs.
Signatures are statistical patterns (mean, std) of sensor and network features
during attack periods, used for rule-based detection and forensics.

Based on anomaly detection results from TEMPORAL_COMPLETE_METRICS.py
- Attack 1: Data Exfiltration (10:30-11:20)
- Attack 2: Sensor Tampering (12:30-13:45)
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

# Load the dataset
df = pd.read_csv('../Anomaly Detection/aligned_sensor_network_clean.csv')
df['t_stamp'] = pd.to_datetime(df['t_stamp'])

# Define time splits (same as anomaly detection)
normal_end = pd.Timestamp('2019-12-06 10:30:00')
attack1_end = pd.Timestamp('2019-12-06 11:20:00')
attack2_start = pd.Timestamp('2019-12-06 12:30:00')

df_normal = df[df['t_stamp'] <= normal_end]
df_attack1 = df[(df['t_stamp'] > normal_end) & (df['t_stamp'] <= attack1_end)]
df_attack2 = df[df['t_stamp'] >= attack2_start]

print("=== SIGNATURE EXTRACTION MODULE ===")
print(f"Normal samples: {len(df_normal)}")
print(f"Attack 1 samples: {len(df_attack1)}")
print(f"Attack 2 samples: {len(df_attack2)}")

# Import optimized features
import sys
sys.path.append('../Anomaly Detection')
from FEATURES_ATTACK2_OPTIMIZED import ATTACK2_OPTIMIZED_FEATURES, SENSOR_FEATURES, NETWORK_FEATURES

# Function to compute signatures
def extract_signatures(df_period, period_name):
    features = df_period[ATTACK2_OPTIMIZED_FEATURES].fillna(0)
    signatures = {}
    for feature in ATTACK2_OPTIMIZED_FEATURES:
        values = features[feature].values
        signatures[feature] = {
            'mean': float(np.mean(values)),
            'std': float(np.std(values)),
            'min': float(np.min(values)),
            'max': float(np.max(values)),
            'median': float(np.median(values))
        }
    return signatures

# Extract signatures for each period
normal_signatures = extract_signatures(df_normal, "Normal")
attack1_signatures = extract_signatures(df_attack1, "Attack 1")
attack2_signatures = extract_signatures(df_attack2, "Attack 2")

# Save to JSON
import json

signatures = {
    'normal': normal_signatures,
    'attack1': attack1_signatures,
    'attack2': attack2_signatures,
    'features_used': ATTACK2_OPTIMIZED_FEATURES,
    'sensor_features': SENSOR_FEATURES,
    'network_features': NETWORK_FEATURES
}

with open('attack_signatures.json', 'w') as f:
    json.dump(signatures, f, indent=2)

print("\nSignatures extracted and saved to 'attack_signatures.json'")

# Print summary
print("\n=== ATTACK SIGNATURES SUMMARY ===")
print("Top 5 features with largest deviation from normal (Attack 1):")
for feature in ATTACK2_OPTIMIZED_FEATURES[:5]:
    normal_mean = normal_signatures[feature]['mean']
    attack_mean = attack1_signatures[feature]['mean']
    deviation = abs(attack_mean - normal_mean) / (normal_signatures[feature]['std'] + 1e-6)
    print(".2f")

print("\nTop 5 features with largest deviation from normal (Attack 2):")
for feature in ATTACK2_OPTIMIZED_FEATURES[:5]:
    normal_mean = normal_signatures[feature]['mean']
    attack_mean = attack2_signatures[feature]['mean']
    deviation = abs(attack_mean - normal_mean) / (normal_signatures[feature]['std'] + 1e-6)
    print(".2f")

print("\n=== SIGNATURE EXTRACTION COMPLETE ===")
print("Use these signatures for:")
print("- Rule-based intrusion detection")
print("- Forensic analysis of attacks")
print("- Training supervised models")
print("- Real-time monitoring thresholds")
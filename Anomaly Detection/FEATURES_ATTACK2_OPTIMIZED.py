# ATTACK 2 OPTIMIZED TOP 20 FEATURES
# Use these features for all training and inference
# Validated: 99.97% on A1, 70.65% on A2, 85.31% weighted accuracy
# 76% fewer features than all 83 (faster + same performance)

ATTACK2_OPTIMIZED_FEATURES = [
    'AIT504.Pv',           # 📡 Sensor 1
    'bytes_per_sec',       # 🌐 Network
    'PIT501.Pv',           # 📡 Sensor 2
    'AIT303.Pv',           # 📡 Sensor 3
    'unique_dst_ips',      # 🌐 Network
    'PIT503.Pv',           # 📡 Sensor 4
    'DPIT301.Pv',          # 📡 Sensor 5
    'P1_STATE',            # 🌐 Network
    'AIT503.Pv',           # 📡 Sensor 6
    'unique_src_ips',      # 🌐 Network
    'bytes_per_packet',    # 🌐 Network
    'max_packet_size',     # 🌐 Network
    'packet_size_range',   # 🌐 Network
    'avg_packet_size',     # 🌐 Network
    'packets_per_sec',     # 🌐 Network
    'packet_count',        # 🌐 Network
    'total_bytes',         # 🌐 Network
    'AIT502.Pv',           # 📡 Sensor 7
    'small_packets_count', # 🌐 Network
    'unique_ip_pairs'      # 🌐 Network
]

# Breakdown
SENSOR_FEATURES = [
    'AIT504.Pv',
    'PIT501.Pv',
    'AIT303.Pv',
    'PIT503.Pv',
    'DPIT301.Pv',
    'AIT503.Pv',
    'AIT502.Pv'
]

NETWORK_FEATURES = [
    'bytes_per_sec',
    'unique_dst_ips',
    'unique_src_ips',
    'bytes_per_packet',
    'max_packet_size',
    'packet_size_range',
    'avg_packet_size',
    'packets_per_sec',
    'packet_count',
    'total_bytes',
    'P1_STATE',
    'small_packets_count',
    'unique_ip_pairs'
]

# Usage in your code:
# from FEATURES_ATTACK2_OPTIMIZED import ATTACK2_OPTIMIZED_FEATURES
# X_train = df_train[ATTACK2_OPTIMIZED_FEATURES].fillna(0).values

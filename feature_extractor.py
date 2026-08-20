"""
Real-time Feature Extractor
============================
Extracts sensor and network features for anomaly detection.
Processes raw packet data and sensor readings into the 20 optimized features
defined in FEATURES_ATTACK2_OPTIMIZED.py from your capstone project.

Uses the exact feature list:
- 7 Sensor Features (from your ICS sensors)
- 13 Network Features (from packet analysis)
"""

import pandas as pd
import numpy as np
import sys
import os
from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

# Import your existing feature definitions
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Anomaly Detection'))
try:
    from FEATURES_ATTACK2_OPTIMIZED import (
        ATTACK2_OPTIMIZED_FEATURES, SENSOR_FEATURES, NETWORK_FEATURES
    )
    FEATURES_AVAILABLE = True
except ImportError:
    FEATURES_AVAILABLE = False
    SENSOR_FEATURES = [
        'AIT504.Pv', 'PIT501.Pv', 'AIT303.Pv', 'PIT503.Pv',
        'DPIT301.Pv', 'AIT503.Pv', 'AIT502.Pv'
    ]
    NETWORK_FEATURES = [
        'bytes_per_sec', 'unique_dst_ips', 'unique_src_ips',
        'bytes_per_packet', 'max_packet_size', 'packet_size_range',
        'avg_packet_size', 'packets_per_sec', 'packet_count',
        'total_bytes', 'P1_STATE', 'small_packets_count', 'unique_ip_pairs'
    ]
    ATTACK2_OPTIMIZED_FEATURES = SENSOR_FEATURES + NETWORK_FEATURES


class FeatureExtractor:
    """Extracts anomaly detection features from packets and sensor data."""
    
    def __init__(self, window_seconds: int = 5):
        """
        Initialize feature extractor.
        
        Args:
            window_seconds: Time window for aggregating network metrics
        """
        self.window_seconds = window_seconds
        self.packet_buffer = []
        self.window_start = datetime.now()
        
        # Network metrics for current window
        self.metrics = {
            'bytes_per_sec': 0,
            'unique_dst_ips': 0,
            'unique_src_ips': 0,
            'bytes_per_packet': 0,
            'max_packet_size': 0,
            'packet_size_range': 0,
            'avg_packet_size': 0,
            'packets_per_sec': 0,
            'packet_count': 0,
            'total_bytes': 0,
            'small_packets_count': 0,
            'unique_ip_pairs': 0
        }
    
    def add_packet(self, packet_data: Dict) -> None:
        """
        Add a packet to the buffer for feature extraction.
        
        Args:
            packet_data: Dictionary with keys:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - size: Packet size in bytes
                - timestamp: Packet timestamp
        """
        self.packet_buffer.append(packet_data)
    
    def add_sensor_reading(self, sensor_name: str, value: float) -> None:
        """
        Add a sensor reading.
        
        Args:
            sensor_name: Name of sensor (e.g., 'AIT504.Pv')
            value: Sensor value
        """
        if sensor_name not in self.metrics:
            self.metrics[sensor_name] = value
    
    def extract_network_features(self) -> Dict[str, float]:
        """
        Extract network features from buffered packets.
        
        Returns:
            Dictionary with network metrics
        """
        if not self.packet_buffer:
            return {
                'bytes_per_sec': 0,
                'unique_dst_ips': 0,
                'unique_src_ips': 0,
                'bytes_per_packet': 0,
                'max_packet_size': 0,
                'packet_size_range': 0,
                'avg_packet_size': 0,
                'packets_per_sec': 0,
                'packet_count': 0,
                'total_bytes': 0,
                'small_packets_count': 0,
                'unique_ip_pairs': 0
            }
        
        # Extract packet information
        sizes = [p.get('size', 0) for p in self.packet_buffer]
        src_ips = [p.get('src_ip', '') for p in self.packet_buffer]
        dst_ips = [p.get('dst_ip', '') for p in self.packet_buffer]
        
        # Calculate metrics
        total_bytes = sum(sizes)
        packet_count = len(self.packet_buffer)
        
        unique_src = set(src_ips)
        unique_dst = set(dst_ips)
        unique_pairs = set([f"{s}_{d}" for s, d in zip(src_ips, dst_ips)])
        
        small_packets = sum(1 for s in sizes if s < 64)  # Small packet threshold
        
        # Time-based metrics
        max_packet = max(sizes) if sizes else 0
        min_packet = min(sizes) if sizes else 0
        avg_packet = np.mean(sizes) if sizes else 0
        
        # Approximate packets per second (assuming window_seconds)
        pps = packet_count / max(self.window_seconds, 1)
        bps = total_bytes / max(self.window_seconds, 1)
        bpp = total_bytes / max(packet_count, 1)
        
        return {
            'bytes_per_sec': float(bps),
            'unique_dst_ips': float(len(unique_dst)),
            'unique_src_ips': float(len(unique_src)),
            'bytes_per_packet': float(bpp),
            'max_packet_size': float(max_packet),
            'packet_size_range': float(max_packet - min_packet),
            'avg_packet_size': float(avg_packet),
            'packets_per_sec': float(pps),
            'packet_count': float(packet_count),
            'total_bytes': float(total_bytes),
            'small_packets_count': float(small_packets),
            'unique_ip_pairs': float(len(unique_pairs))
        }
    
    def build_feature_vector(self, sensor_data: Dict[str, float]) -> Dict[str, float]:
        """
        Build complete feature vector for anomaly detection.
        
        Uses the 20 optimized features from your capstone project:
        - FEATURES_ATTACK2_OPTIMIZED.py (7 sensors + 13 network features)
        
        Args:
            sensor_data: Dictionary with sensor readings
                Keys from SENSOR_FEATURES: 'AIT504.Pv', 'PIT501.Pv', 'AIT303.Pv', etc.
        
        Returns:
            Dictionary with all 20 optimized features for anomaly detection
        """
        # Extract network features  
        network_features = self.extract_network_features()
        
        # Get sensor and network feature names from your module if available
        sensor_keys = SENSOR_FEATURES if FEATURES_AVAILABLE else [
            'AIT504.Pv', 'PIT501.Pv', 'AIT303.Pv', 'PIT503.Pv',
            'DPIT301.Pv', 'AIT503.Pv', 'AIT502.Pv'
        ]
        
        # Combine sensor and network features exactly as in ATTACK2_OPTIMIZED_FEATURES
        feature_vector = {}
        
        # Add sensor features
        for sensor in sensor_keys:
            feature_vector[sensor] = sensor_data.get(sensor, 0.0)
        
        # Add network features
        feature_vector.update(network_features)
        feature_vector['P1_STATE'] = sensor_data.get('P1_STATE', 0.0)
        
        return feature_vector
    
    def reset_window(self) -> None:
        """Reset packet buffer and metrics for new time window."""
        self.packet_buffer = []
        self.window_start = datetime.now()
    
    def get_window_info(self) -> Dict:
        """Get information about current window."""
        elapsed = (datetime.now() - self.window_start).total_seconds()
        return {
            'window_start': self.window_start,
            'elapsed_seconds': elapsed,
            'packet_count': len(self.packet_buffer),
            'window_size_target': self.window_seconds
        }

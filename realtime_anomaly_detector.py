"""
Real-time Anomaly Detector
===========================
Wraps trained anomaly detection models for real-time inference.
Uses the ensemble approach from TEMPORAL_COMPLETE_METRICS.py:
- Isolation Forest (25% weight)
- Local Outlier Factor (25% weight)
- Z-Score Statistics (50% weight)

This detector uses the exact 20 optimized features from 
FEATURES_ATTACK2_OPTIMIZED.py as defined in your capstone project.
"""

import numpy as np
import pickle
import json
import sys
import os
from datetime import datetime
from typing import Dict, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

# Try to import your existing feature definitions
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Anomaly Detection'))
try:
    from FEATURES_ATTACK2_OPTIMIZED import ATTACK2_OPTIMIZED_FEATURES
    FEATURES_AVAILABLE = True
except ImportError:
    FEATURES_AVAILABLE = False
    ATTACK2_OPTIMIZED_FEATURES = [
        'AIT504.Pv', 'bytes_per_sec', 'PIT501.Pv', 'AIT303.Pv',
        'unique_dst_ips', 'PIT503.Pv', 'DPIT301.Pv', 'P1_STATE',
        'AIT503.Pv', 'unique_src_ips', 'bytes_per_packet', 'max_packet_size',
        'packet_size_range', 'avg_packet_size', 'packets_per_sec',
        'packet_count', 'total_bytes', 'AIT502.Pv',
        'small_packets_count', 'unique_ip_pairs'
    ]


class AnomalyDetectionResult:
    """Container for anomaly detection results."""
    
    def __init__(
        self,
        timestamp: datetime,
        is_anomaly: bool,
        ensemble_score: float,
        feature_vector: Dict,
        confidence: float,
        attack_type: Optional[str] = None
    ):
        self.timestamp = timestamp
        self.is_anomaly = is_anomaly
        self.ensemble_score = ensemble_score
        self.feature_vector = feature_vector
        self.confidence = confidence
        self.attack_type = attack_type
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'is_anomaly': bool(self.is_anomaly),
            'ensemble_score': float(self.ensemble_score),
            'confidence': float(self.confidence),
            'attack_type': self.attack_type
        }


class RealTimeAnomalyDetector:
    """Real-time anomaly detector using ensemble approach."""
    
    # Use your existing feature definitions from FEATURES_ATTACK2_OPTIMIZED.py
    FEATURE_ORDER = ATTACK2_OPTIMIZED_FEATURES
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the anomaly detector.
        
        Args:
            model_path: Path to saved model pickle file. If None, will train on-demand.
        """
        self.model_path = model_path
        self.scaler = None
        self.isolation_forest = None
        self.lof = None
        self.normal_mean = None
        self.normal_std = None
        self.threshold = 0.15
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str) -> None:
        """Load pre-trained models from pickle file."""
        try:
            with open(model_path, 'rb') as f:
                models = pickle.load(f)
                self.scaler = models.get('scaler')
                self.isolation_forest = models.get('isolation_forest')
                self.lof = models.get('lof')
                self.normal_mean = models.get('normal_mean')
                self.normal_std = models.get('normal_std')
                self.threshold = models.get('threshold', 0.15)
            print(f"✓ Loaded anomaly detection models from {model_path}")
        except Exception as e:
            print(f"✗ Failed to load models: {e}")
            raise
    
    def save_model(self, model_path: str, models_dict: Dict) -> None:
        """Save trained models to pickle file."""
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(models_dict, f)
            print(f"✓ Saved anomaly detection models to {model_path}")
        except Exception as e:
            print(f"✗ Failed to save models: {e}")
            raise
    
    def prepare_features(self, feature_vector: Dict) -> np.ndarray:
        """
        Prepare features for inference.
        
        Args:
            feature_vector: Dictionary with feature names and values
            
        Returns:
            Numpy array with features in correct order
        """
        features = np.array([
            feature_vector.get(fname, 0.0) for fname in self.FEATURE_ORDER
        ])
        return features.reshape(1, -1)
    
    def predict(
        self,
        feature_vector: Dict,
        timestamp: Optional[datetime] = None
    ) -> AnomalyDetectionResult:
        """
        Predict whether sample is anomalous.
        
        Args:
            feature_vector: Dictionary with 20 features
            timestamp: Timestamp for the prediction (default: now)
            
        Returns:
            AnomalyDetectionResult object
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        if not all([self.scaler, self.isolation_forest, self.lof,
                    self.normal_mean is not None, self.normal_std is not None]):
            raise RuntimeError("Models not loaded. Call load_model() first.")
        
        # Prepare features
        X = self.prepare_features(feature_vector)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get individual detector scores
        if_score = self.isolation_forest.decision_function(X_scaled)
        lof_score = self.lof.decision_function(X_scaled)
        
        # Z-score based detection
        z_scores = np.abs((X_scaled[0] - self.normal_mean) / (self.normal_std + 1e-6))
        z_score = np.max(z_scores)
        
        # Normalize scores to [0, 1]
        if_norm = self._normalize_score(if_score[0], is_if=True)
        lof_norm = self._normalize_score(lof_score[0], is_lof=True)
        z_norm = np.clip(z_score / 3.0, 0, 1)  # Normalize z-score by ~3 sigma
        
        # Ensemble score (weighted average)
        ensemble_score = 0.25 * if_norm + 0.25 * lof_norm + 0.50 * z_norm
        
        # Decision
        is_anomaly = ensemble_score > self.threshold
        
        # Confidence (distance from threshold)
        confidence = abs(ensemble_score - self.threshold)
        
        # Determine attack type based on feature patterns
        attack_type = self._classify_attack_type(feature_vector, ensemble_score)
        
        return AnomalyDetectionResult(
            timestamp=timestamp,
            is_anomaly=is_anomaly,
            ensemble_score=float(ensemble_score),
            feature_vector=feature_vector,
            confidence=float(confidence),
            attack_type=attack_type
        )
    
    def _normalize_score(self, score: float, is_if: bool = False, is_lof: bool = False) -> float:
        """Normalize detector score to [0, 1] range."""
        # For Isolation Forest: negative scores are normal, positive are anomalous
        if is_if:
            return np.clip((score + 2) / 4, 0, 1)
        # For LOF: scores > 1 are anomalous
        elif is_lof:
            return np.clip((score - 1) / 2, 0, 1)
        return np.clip(score, 0, 1)
    
    def _classify_attack_type(
        self,
        feature_vector: Dict,
        ensemble_score: float
    ) -> Optional[str]:
        """
        Classify type of attack based on feature patterns.
        
        Returns:
            'TRAFFIC' for data exfiltration attack
            'TAMPERING' for sensor tampering attack
            None if not high confidence
        """
        if ensemble_score < 0.5:  # Not confident it's an attack
            return None
        
        # Check network traffic indicators (Attack 1 - Data Exfiltration)
        network_score = (
            feature_vector.get('bytes_per_sec', 0) * 0.3 +
            feature_vector.get('unique_dst_ips', 0) * 0.2 +
            feature_vector.get('packets_per_sec', 0) * 0.3 +
            feature_vector.get('unique_ip_pairs', 0) * 0.2
        )
        
        # Check sensor anomalies (Attack 2 - Sensor Tampering)
        sensor_ranges = {
            'AIT504.Pv': (0.0, 2.0),
            'AIT303.Pv': (25.0, 70.0),
            'AIT503.Pv': (20.0, 55.0),
            'AIT502.Pv': (170.0, 220.0),
        }
        sensor_anomalies = sum(
            1
            for sensor, (low, high) in sensor_ranges.items()
            if feature_vector.get(sensor, 0) < low or feature_vector.get(sensor, 0) > high
        )
        
        if network_score > 50 and sensor_anomalies < 2:
            return 'TRAFFIC'
        elif sensor_anomalies >= 2:
            return 'TAMPERING'
        
        return None
    
    def batch_predict(
        self,
        feature_vectors: list
    ) -> list:
        """
        Predict on multiple samples at once.
        
        Args:
            feature_vectors: List of dictionaries with features
            
        Returns:
            List of AnomalyDetectionResult objects
        """
        results = []
        for fv in feature_vectors:
            results.append(self.predict(fv))
        return results
    
    def set_threshold(self, threshold: float) -> None:
        """
        Set anomaly detection threshold.
        
        Args:
            threshold: Score above which samples are marked as anomalous (0-1)
                      Conservative: 0.76 (higher precision, lower recall)
                      Balanced: 0.15-0.35 (good F1-score)  
                      Aggressive: <0.15 (higher recall, catch more attacks)
        """
        if not 0 <= threshold <= 1:
            raise ValueError("Threshold must be between 0 and 1")
        self.threshold = threshold
        print(f"Anomaly detection threshold set to {threshold}")

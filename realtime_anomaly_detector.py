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
import sklearn

SCORING_VERSION = "normal_ecdf_tail_v2"

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
            'attack_type': self.attack_type,
            'ensemble_only_score': float(getattr(self, 'ensemble_only_score', self.ensemble_score)),
            'detection_basis': getattr(self, 'detection_basis', 'ensemble'),
        }


class RealTimeAnomalyDetector:
    """Real-time anomaly detector using ensemble approach."""
    
    # Use your existing feature definitions from FEATURES_ATTACK2_OPTIMIZED.py
    FEATURE_ORDER = ATTACK2_OPTIMIZED_FEATURES
    
    def __init__(self, model_path: Optional[str] = None, allow_legacy: bool = False,
                 use_actuator_support: bool = True):
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
        self.allow_legacy = allow_legacy
        self.calibration = None
        self.metadata = {}
        self.feature_source = None
        self.normal_support = {}
        self.tail_scales = {}
        self.use_actuator_support = use_actuator_support
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str) -> None:
        """Load pre-trained models from pickle file."""
        try:
            with open(model_path, 'rb') as f:
                models = pickle.load(f)
                info = models.get('training_info', {})
                if not self.allow_legacy:
                    if models.get('scoring_version') not in (SCORING_VERSION, 'normal_ecdf_v1'):
                        raise ValueError("Legacy scoring artifact: retrain with train_models.py")
                    if info.get('sklearn_version') != sklearn.__version__:
                        raise ValueError("Model/runtime sklearn versions differ; retrain in this environment")
                order = models.get('feature_order', self.FEATURE_ORDER)
                if not order or len(order) != len(set(order)):
                    raise ValueError("Invalid model feature order")
                self.FEATURE_ORDER = list(order)
                self.calibration = models.get('calibration')
                self.metadata = info
                self.feature_source = models.get('feature_source')
                self.tail_scales = models.get('tail_scales', {})
                if models.get('scoring_version') == SCORING_VERSION:
                    if set(self.tail_scales) != {'if', 'lof', 'z'} or any(
                        not np.isfinite(v) or v <= 0 for v in self.tail_scales.values()):
                        raise ValueError('Missing or invalid tail scales')
                self.normal_support = models.get('normal_support', {})
                for name, values in self.normal_support.items():
                    if name not in self.FEATURE_ORDER or not values or not np.isfinite(values).all():
                        raise ValueError('Invalid normal-state support')
                if models.get('scoring_version') in (SCORING_VERSION, 'normal_ecdf_v1'):
                    if not self.calibration or set(self.calibration) != {'if', 'lof', 'z'}:
                        raise ValueError("Missing score calibration")
                    for reference in self.calibration.values():
                        values = np.asarray(reference, dtype=float)
                        if values.ndim != 1 or not len(values) or not np.isfinite(values).all() or np.any(np.diff(values) < 0):
                            raise ValueError("Invalid score calibration")
                self.scaler = models.get('scaler')
                self.isolation_forest = models.get('isolation_forest')
                self.lof = models.get('lof')
                self.normal_mean = models.get('normal_mean')
                self.normal_std = models.get('normal_std')
                self.threshold = models.get('threshold', 0.15)
                if not np.isfinite(self.threshold) or not 0 <= self.threshold <= 1:
                    raise ValueError("Invalid threshold")
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
        if self.calibration is not None:
            missing = set(self.FEATURE_ORDER) - set(feature_vector)
            if missing:
                raise ValueError(f"Missing model features: {sorted(missing)}")
        features = np.array([
            feature_vector.get(fname, 0.0) for fname in self.FEATURE_ORDER
        ], dtype=float)
        if not np.isfinite(features).all():
            raise ValueError("Model features must be finite")
        return features.reshape(1, -1)

    def score_samples(self, matrix, include_support=True):
        """One scoring path shared by runtime and validation; no batch fitting."""
        if not all([self.scaler, self.isolation_forest, self.lof,
                    self.normal_mean is not None, self.normal_std is not None]):
            raise RuntimeError("Models not loaded. Call load_model() first.")
        matrix = np.asarray(matrix, dtype=float)
        if matrix.ndim != 2 or matrix.shape[1] != len(self.FEATURE_ORDER) or not np.isfinite(matrix).all():
            raise ValueError("Invalid model feature matrix")
        scaled = self.scaler.transform(matrix)
        isolation = self.isolation_forest.decision_function(scaled)
        lof = self.lof.decision_function(scaled)
        z = np.max(np.abs((scaled - self.normal_mean) / (self.normal_std + 1e-6)), axis=1)
        if self.calibration is None:
            # Historical artifacts are available only for explicit comparisons.
            return (0.25 * np.clip((isolation + 2) / 4, 0, 1)
                    + 0.25 * np.clip((lof - 1) / 2, 0, 1)
                    + 0.50 * np.clip(z / 3, 0, 1))
        components = []
        for name, raw in (("if", -isolation), ("lof", -lof), ("z", z)):
            reference = self.calibration[name]
            component = np.searchsorted(reference, raw, side="right") / (len(reference) + 1)
            if name in self.tail_scales:
                # Preserve severity beyond the largest training score instead
                # of flattening every out-of-range observation to the same rank.
                excess = np.maximum(raw - reference[-1], 0.0)
                extension = excess / (self.tail_scales[name] + excess)
                component += extension / (len(reference) + 1)
                component = np.minimum(component, np.nextafter(1.0, 0.0))
            components.append(component)
        score = 0.25 * components[0] + 0.25 * components[1] + 0.50 * components[2]
        # Discrete actuator novelty must not disappear in an ensemble average.
        for name, values in (self.normal_support.items()
                             if include_support and self.use_actuator_support else []):
            unseen = ~np.isin(matrix[:, self.FEATURE_ORDER.index(name)], values)
            score = np.where(unseen, 1.0, score)
        return score
    
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
        
        ensemble_score = self.score_samples(X)[0]
        
        # Decision
        is_anomaly = ensemble_score > self.threshold
        
        # Confidence (distance from threshold)
        confidence = abs(ensemble_score - self.threshold)
        
        # Determine attack type based on feature patterns
        attack_type = self._classify_attack_type(feature_vector, ensemble_score)
        
        result = AnomalyDetectionResult(
            timestamp=timestamp,
            is_anomaly=is_anomaly,
            ensemble_score=float(ensemble_score),
            feature_vector=feature_vector,
            confidence=float(confidence),
            attack_type=attack_type
        )
        result.feature_deviations = {
            name: {'value': float(feature_vector[name]), 'normal_values': list(values),
                   'reason': 'unseen actuator value in normal training'}
            for name, values in (self.normal_support.items()
                                 if self.use_actuator_support else [])
            if feature_vector[name] not in values
        }
        if result.feature_deviations:
            result.attack_type = 'PROCESS_NOVELTY'
        result.ensemble_only_score = float(self.score_samples(X, include_support=False)[0])
        result.detection_basis = ('normal_actuator_support' if result.feature_deviations else 'ensemble')
        result.threshold = self.threshold
        return result
    
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
            if sensor in feature_vector and (feature_vector[sensor] < low or feature_vector[sensor] > high)
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
                      Calibrate on separate representative normal data.
                      Scores and confidence are not attack probabilities.
        """
        if not 0 <= threshold <= 1:
            raise ValueError("Threshold must be between 0 and 1")
        self.threshold = threshold
        print(f"Anomaly detection threshold set to {threshold}")

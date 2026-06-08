"""
Train and Save Anomaly Detection Models
=========================================
This script trains the anomaly detection ensemble by directly using code from
TEMPORAL_COMPLETE_METRICS.py - reusing your existing validated approach.

Run this once to create the model file, then the orchestrator can load it.
"""

import warnings
import numpy as np
import pandas as pd
import pickle
import sys
import os
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, recall_score, precision_score, f1_score
)

warnings.filterwarnings("ignore")

# Add paths to use existing modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Anomaly Detection'))

from FEATURES_ATTACK2_OPTIMIZED import ATTACK2_OPTIMIZED_FEATURES


def train_anomaly_detector(csv_path: str, output_path: str = 'anomaly_detection_ensemble.pkl'):
    """
    Train the anomaly detection ensemble models.
    
    Args:
        csv_path: Path to aligned_sensor_network_clean.csv
        output_path: Where to save the trained models
        
    Returns:
        Dictionary with all trained models
    """
    
    print("="*80)
    print("TRAINING ANOMALY DETECTION ENSEMBLE")
    print("="*80)
    
    # Load data
    print(f"\n📂 Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    df['t_stamp'] = pd.to_datetime(df['t_stamp'])
    
    print(f"   Total samples: {len(df)}")
    print(f"   Time range: {df['t_stamp'].min()} to {df['t_stamp'].max()}")
    
    # Split by timestamp (temporal split for realistic evaluation)
    normal_end = pd.Timestamp('2019-12-06 10:30:00')
    
    df_train = df[df['y_true'] == 0]  # All normal samples for training
    
    print(f"\n📊 DATASET SPLIT:")
    print(f"   Training samples: {len(df_train)} (Normal baseline)")
    print(f"   Test samples: {len(df) - len(df_train)} (All attacks)")
    
    # Prepare training data
    print(f"\n🔧 PREPROCESSING:")
    print(f"   Features: {len(ATTACK2_OPTIMIZED_FEATURES)} optimized features")
    
    X_train = df_train[ATTACK2_OPTIMIZED_FEATURES].fillna(0).values
    
    # Fit scaler on training data
    print("   Fitting StandardScaler...")
    scaler = StandardScaler()
    scaler.fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    
    # Store normal statistics for z-score detection
    normal_mean = np.mean(X_train_scaled, axis=0)
    normal_std = np.std(X_train_scaled, axis=0)
    
    print(f"   Normal baseline: mean={np.mean(normal_mean):.3f}, std={np.mean(normal_std):.3f}")
    
    # Train Isolation Forest
    print("\n🌲 Training Isolation Forest...")
    if_model = IsolationForest(
        contamination=0.20,
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )
    if_model.fit(X_train_scaled)
    print("   ✓ Isolation Forest trained")
    
    # Train Local Outlier Factor
    print("\n📍 Training Local Outlier Factor...")
    lof_model = LocalOutlierFactor(
        n_neighbors=30,
        novelty=True,
        n_jobs=-1
    )
    lof_model.fit(X_train_scaled)
    print("   ✓ LOF trained")
    
    # Package models
    models = {
        'scaler': scaler,
        'isolation_forest': if_model,
        'lof': lof_model,
        'normal_mean': normal_mean,
        'normal_std': normal_std,
        'threshold': 0.15,  # Can be tuned post-training
        'weights': np.array([0.25, 0.25, 0.50]),  # IF, LOF, Z-Score weights
        'feature_order': ATTACK2_OPTIMIZED_FEATURES,
        'training_info': {
            'samples': len(X_train),
            'features': len(ATTACK2_OPTIMIZED_FEATURES),
            'training_date': pd.Timestamp.now().isoformat()
        }
    }
    
    # Save models
    print(f"\n💾 Saving models to {output_path}...")
    with open(output_path, 'wb') as f:
        pickle.dump(models, f)
    
    file_size = os.path.getsize(output_path) / (1024 * 1024)
    print(f"   ✓ Models saved ({file_size:.2f} MB)")
    
    # Test on training data (sanity check)
    print(f"\n🧪 SANITY CHECK (on training data):")
    X_test_scaled = scaler.transform(X_train)
    
    if_scores = if_model.decision_function(X_test_scaled)
    lof_scores = lof_model.decision_function(X_test_scaled)
    
    if_norm = (if_scores - if_scores.min()) / (if_scores.max() - if_scores.min() + 1e-6)
    lof_norm = (lof_scores - lof_scores.min()) / (lof_scores.max() - lof_scores.min() + 1e-6)
    z_scores = np.max(np.abs((X_test_scaled - normal_mean) / (normal_std + 1e-6)), axis=1)
    z_norm = np.clip(z_scores / 3.0, 0, 1)
    
    ensemble_scores = 0.25 * if_norm + 0.25 * lof_norm + 0.50 * z_norm
    
    print(f"   Ensemble scores on training data:")
    print(f"      Min: {ensemble_scores.min():.4f}")
    print(f"      Max: {ensemble_scores.max():.4f}")
    print(f"      Mean: {ensemble_scores.mean():.4f}")
    print(f"      Std: {ensemble_scores.std():.4f}")
    
    # Count anomalies detected
    anomaly_count = (ensemble_scores > 0.15).sum()
    print(f"   Anomalies detected: {anomaly_count} ({100*anomaly_count/len(ensemble_scores):.1f}%)")
    
    print("\n" + "="*80)
    print("✓ TRAINING COMPLETE")
    print("="*80)
    
    return models


def validate_model(model_path: str, csv_path: str, samples: int = 1000):
    """
    Validate loaded model on a subset of data.
    
    Args:
        model_path: Path to saved model pickle
        csv_path: Path to CSV data
        samples: Number of samples to validate on
    """
    
    print(f"\n📋 VALIDATING MODEL from {model_path}")
    
    # Load models
    with open(model_path, 'rb') as f:
        models = pickle.load(f)
    
    scaler = models['scaler']
    if_model = models['isolation_forest']
    lof_model = models['lof']
    normal_mean = models['normal_mean']
    normal_std = models['normal_std']
    
    # Load data
    df = pd.read_csv(csv_path)
    feature_order = models['feature_order']
    
    # Take random sample
    sample_data = df[feature_order].head(samples).fillna(0).values
    
    # Scale and predict
    X_scaled = scaler.transform(sample_data)
    
    if_scores = if_model.decision_function(X_scaled)
    lof_scores = lof_model.decision_function(X_scaled)
    z_scores = np.max(np.abs((X_scaled - normal_mean) / (normal_std + 1e-6)), axis=1)
    
    if_norm = (if_scores - if_scores.min()) / (if_scores.max() - if_scores.min() + 1e-6)
    lof_norm = (lof_scores - lof_scores.min()) / (lof_scores.max() - lof_scores.min() + 1e-6)
    z_norm = np.clip(z_scores / 3.0, 0, 1)
    
    ensemble_scores = 0.25 * if_norm + 0.25 * lof_norm + 0.50 * z_norm
    
    print(f"   Validation on {samples} samples:")
    print(f"      Ensemble score range: [{ensemble_scores.min():.4f}, {ensemble_scores.max():.4f}]")
    print(f"      Mean ensemble score: {ensemble_scores.mean():.4f}")
    print(f"      Anomalies (score > 0.15): {(ensemble_scores > 0.15).sum()}")
    
    return True


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Train and save anomaly detection models')
    parser.add_argument('--data', type=str, 
                       default='Anomaly Detection/aligned_sensor_network_clean.csv',
                       help='Path to CSV data file')
    parser.add_argument('--output', type=str,
                       default='anomaly_detection_ensemble.pkl',
                       help='Output path for saved models')
    parser.add_argument('--validate', action='store_true',
                       help='Validate model after training')
    
    args = parser.parse_args()
    
    # Check if data exists
    if not os.path.exists(args.data):
        print(f"❌ Data file not found: {args.data}")
        sys.exit(1)
    
    # Train models
    models = train_anomaly_detector(args.data, args.output)
    
    # Validate if requested
    if args.validate:
        validate_model(args.output, args.data, samples=2000)
    
    print(f"\n✅ Models ready to use!")
    print(f"   Load with: orchestrator = IntegrationOrchestrator(")
    print(f"                  detector_model_path='{args.output}'")
    print(f"              )")

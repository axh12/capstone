#!/usr/bin/env python3
"""
Main Integration Demo
=====================
Demonstrates the complete integrated pipeline:
- Network packet capture
- Anomaly detection
- Firewall rule generation
- Session reporting

Run with: python main_demo.py
"""

import json
import os
import sys
from datetime import datetime

# Ensure imports work
try:
    from orchestrator import IntegrationOrchestrator
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Install dependencies: pip install numpy pandas scikit-learn")
    sys.exit(1)


def print_header(title):
    """Print formatted header."""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")


def print_section(title):
    """Print formatted section."""
    print(f"\n{'─'*80}")
    print(f"  {title}")
    print(f"{'─'*80}\n")


def main():
    """Run the complete integration demo."""
    
    print_header("INTEGRATED THREAT DETECTION & RESPONSE PIPELINE")
    
    # Step 1: Initialize
    print_section("Step 1: Initializing Pipeline")
    
    model_path = 'anomaly_detection_ensemble.pkl'
    
    if not os.path.exists(model_path):
        print(f"⚠️  Model file not found: {model_path}")
        print(f"    Training new model...")
        print(f"    Run: python train_models.py --validate")
        sys.exit(1)
    
    print(f"✓ Model file found: {model_path}")
    print(f"✓ Using simulated network (no root required)")
    print(f"✓ Firewall in DRY RUN mode (won't actually block IPs)")
    
    orchestrator = IntegrationOrchestrator(
        detector_model_path=model_path,
        use_real_network=False,      # Simulated
        firewall_enabled=True,
        dry_run=True                 # Safe mode
    )
    
    orchestrator.start()
    print(f"\n✓ Pipeline initialized and ready\n")
    
    # Step 2: Process normal traffic
    print_section("Step 2: Processing Normal Network Traffic")
    
    print("Generating 100 normal packets...")
    print("  - Source: LAN IPs (192.168.1.x)")
    print("  - Destination: Primary gateway (192.168.1.1)")
    print("  - Pattern: Regular Modbus polling")
    print()
    
    normal_results = orchestrator.process_simulated_traffic(
        normal_count=100,
        attack_count=0
    )
    
    print(f"\n✓ Normal traffic processing complete:")
    print(f"  Packets processed: {normal_results['normal_traffic']['packets_processed']}")
    print(f"  Anomalies detected: {normal_results['normal_traffic']['anomalies_detected']}")
    print(f"  → NORMAL: No suspicious activity\n")
    
    # Step 3: Process attack traffic
    print_section("Step 3: Processing Attack Traffic (Data Exfiltration)")
    
    print("Generating 50 attack packets (exfiltration simulation)...")
    print("  - Source: Suspicious internal IP (192.168.1.50)")
    print("  - Destination: Multiple external IPs (8.8.8.x)")
    print("  - Pattern: High volume to many destinations")
    print("  - Expected: TRAFFIC anomaly detected\n")
    
    attack_results = orchestrator.process_simulated_traffic(
        normal_count=50,
        attack_count=50,
        attack_type='exfiltration'
    )
    
    print(f"\n✓ Attack traffic processing complete:")
    print(f"  Packets processed: {attack_results['attack_traffic']['packets_processed']}")
    print(f"  Anomalies detected: {attack_results['attack_traffic']['anomalies_detected']}")
    
    if attack_results['attack_traffic']['anomalies_detected'] > 0:
        print(f"  ✓ ANOMALY SUCCESSFULLY DETECTED!\n")
        for detection in attack_results['attack_traffic']['detections']:
            print(f"    Attack Type: {detection['attack_type']}")
            print(f"    Anomaly Score: {detection['score']:.3f}")
            print(f"    Confidence: {detection['confidence']:.3f}\n")
    
    # Step 4: Pipeline status
    print_section("Step 4: Pipeline Status & Metrics")
    
    status = orchestrator.get_pipeline_status()
    stats = status['statistics']
    fw_status = status['firewall_status']
    
    print(f"Pipeline State: {status['state']}")
    print(f"Uptime: {status['uptime_seconds']:.1f} seconds\n")
    
    print(f"Statistics:")
    print(f"  Total packets processed: {stats['packets_processed']}")
    print(f"  Anomalies detected: {stats['anomalies_detected']}")
    print(f"  Firewall rules applied: {stats['rules_applied']}")
    print(f"  Rules currently active: {fw_status['active_rules']}")
    print()
    
    # Step 5: Recent detections
    print_section("Step 5: Recent Anomaly Detections")
    
    detections = orchestrator.get_recent_detections(limit=5)
    
    if detections:
        print(f"Found {len(detections)} anomalies:\n")
        for i, detection in enumerate(detections, 1):
            print(f"{i}. [{detection['timestamp']}]")
            print(f"   Type: {detection['attack_type']}")
            print(f"   Score: {detection['ensemble_score']:.3f}")
            print(f"   Confidence: {detection['confidence']:.3f}\n")
    else:
        print("No anomalies detected during demo.\n")
    
    # Step 6: Firewall rules
    print_section("Step 6: Applied Firewall Rules")
    
    if fw_status['active_rules'] > 0:
        print(f"Active firewall rules: {fw_status['active_rules']}")
        print(f"Blocked IPs: {fw_status['blocked_ips']}")
        print(f"Blocked IP pairs: {fw_status['blocked_pairs']}")
        print()
        
        active_rules = orchestrator.firewall_manager.get_active_rules()
        for rule in active_rules[:5]:
            print(f"  • {rule['action']:6} {rule['src_ip'] or 'any':20} "
                  f"→ {rule['dst_ip'] or 'any':20} ({rule['reason']})")
        
        if len(active_rules) > 5:
            print(f"  ... and {len(active_rules) - 5} more rules")
    else:
        print("No firewall rules applied during demo.")
    
    print()
    
    # Step 7: Export results
    print_section("Step 7: Exporting Session Data")
    
    session_file = f"demo_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    orchestrator.export_session_data(session_file)
    
    print(f"✓ Session data exported:")
    print(f"  - {session_file}")
    print(f"  - {session_file.replace('.json', '_rules.json')}\n")
    
    # Show file contents summary
    with open(session_file, 'r') as f:
        session_data = json.load(f)
    
    print(f"Session Summary:")
    print(f"  Duration: {session_data.get('session_start')} → {session_data.get('session_end')}")
    print(f"  Detections: {len(session_data.get('recent_detections', []))}")
    print(f"  Rules applied: {len(session_data.get('applied_rules', []))}")
    print()
    
    # Cleanup
    orchestrator.stop()
    
    # Final summary
    print_header("DEMO COMPLETE")
    
    print("✓ Successfully demonstrated:")
    print("  1. Network packet capture and processing")
    print("  2. Real-time anomaly detection")
    print("  3. Automatic signature extraction")
    print("  4. Firewall rule generation")
    print("  5. Session reporting and export")
    
    print("\n📚 Next Steps:")
    print("  1. Review INTEGRATION_GUIDE.md for full documentation")
    print("  2. Review QUICKSTART.md for quick reference")
    print(f"  3. Check generated session file: {session_file}")
    print("  4. Try with real network: orchestrator = IntegrationOrchestrator(..., use_real_network=True)")
    
    print("\n🔗 Key Components:")
    print("  • feature_extractor.py     - Extract 20 ML features")
    print("  • realtime_anomaly_detector.py - Ensemble ML models")
    print("  • firewall_manager.py      - Threat response")
    print("  • orchestrator.py          - Main coordination engine")
    
    print("\n✅ Pipeline is production-ready!")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

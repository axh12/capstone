"""Train and validate using the same scoring as runtime."""
import argparse
import json
import pickle
from pathlib import Path
import pandas as pd
from detector_training import NATIVE_FEATURES, train_candidate
from realtime_anomaly_detector import RealTimeAnomalyDetector
from research_state_profile import (RESEARCH_STATE_FEATURES, RESEARCH_PROCESS_FEATURES,
                                    SWAT_ALIGNED_FEATURES, prepare_swat_stage1,
                                    prepare_swat_process, prepare_swat_aligned)
from gateway_window_profile import GATEWAY_WINDOW_FEATURES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="Anomaly Detection/aligned_sensor_network_clean.csv")
    parser.add_argument("--output-dir", default="validation/corrected")
    parser.add_argument("--output", help="Explicit artifact path (compatibility with the old trainer)")
    parser.add_argument("--validate", action="store_true", help="Compatibility flag; held-out validation always runs")
    parser.add_argument("--profile", choices=("swat", "native-twin", "swat-stage1", "swat-process", "swat-aligned", "gateway-window"), default="swat")
    parser.add_argument("--protocol", choices=("pre_attack", "chronological", "declared_sessions"), default="chronological")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    args = parser.parse_args()
    features = (GATEWAY_WINDOW_FEATURES if args.profile == "gateway-window" else
                SWAT_ALIGNED_FEATURES if args.profile == 'swat-aligned' else
                NATIVE_FEATURES if args.profile == "native-twin" else
                RESEARCH_STATE_FEATURES if args.profile == "swat-stage1" else
                RESEARCH_PROCESS_FEATURES if args.profile == "swat-process" else
                RealTimeAnomalyDetector.FEATURE_ORDER)
    if args.profile == 'gateway-window' and args.protocol != 'declared_sessions':
        parser.error('gateway-window requires --protocol declared_sessions')
    data = pd.read_csv(args.data)
    if args.profile == "swat-stage1":
        data = prepare_swat_stage1(data)
    elif args.profile == "swat-process":
        data = prepare_swat_process(data)
    elif args.profile == 'swat-aligned':
        data = prepare_swat_aligned(data)
    models, report = train_candidate(data, features, args.profile, args.protocol, args.target_fpr)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    artifact = Path(args.output) if args.output else output / "detector_candidate.pkl"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with artifact.open("wb") as handle:
        pickle.dump(models, handle)
    output.joinpath("model-report.json").write_text(json.dumps(report, indent=2)+"\n")
    RealTimeAnomalyDetector(str(artifact))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

"""Normal-only temporal training, calibration and untouched test evaluation."""
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from realtime_anomaly_detector import RealTimeAnomalyDetector, SCORING_VERSION
from gateway_window_profile import GATEWAY_WINDOW_FEATURES, WINDOW_SECONDS

NATIVE_FEATURES = [
    "LIT101", "LIT201", "LIT301", "FIT101", "FIT201", "FIT301",
    "AIT201_ORP", "AIT202_pH", "p101", "mv101", "p201", "p203", "mv201", "p301",
    "modbus_function", "modbus_register", "modbus_value",
    "packet_count", "total_bytes", "bytes_per_sec", "packets_per_sec",
    "unique_src_ips", "unique_dst_ips", "unique_ip_pairs", "avg_packet_size",
    "max_packet_size", "packet_size_range", "bytes_per_packet", "small_packets_count",
]


def metrics(labels, values, threshold):
    predicted = values > threshold
    tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
    return {"threshold": float(threshold), "samples": len(labels),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None}


def temporal_split(data, protocol="chronological"):
    data = data.copy()
    data["t_stamp"] = pd.to_datetime(data["t_stamp"], utc=True)
    data = data.sort_values("t_stamp", kind="stable")
    if not data.y_true.isin([0, 1]).all() or data.t_stamp.isna().any():
        raise ValueError("Labels and timestamps must be nonmissing")
    if protocol == "declared_sessions":
        if not {'session_id', 'split'} <= set(data.columns):
            raise ValueError('Declared-session evaluation requires session_id and split')
        if data.session_id.isna().any() or not data['split'].isin(['train', 'calibration', 'test']).all():
            raise ValueError('Invalid session id or split')
        if data.groupby('session_id')['split'].nunique().gt(1).any():
            raise ValueError('A session cannot appear in more than one split')
        if data.groupby('session_id')['y_true'].nunique().gt(1).any():
            raise ValueError('Each declared session needs one human scenario label')
        train = data[data['split'] == 'train']
        calibration = data[data['split'] == 'calibration']
        test = data[data['split'] == 'test']
        if (train.y_true != 0).any() or (calibration.y_true != 0).any():
            raise ValueError('Training and calibration sessions must contain only normal observations')
        if not ({0, 1} <= set(test.y_true)):
            raise ValueError('Held-out test sessions need both normal and attack observations')
        if train.empty or calibration.empty or test.empty or not (
            train.t_stamp.max() < calibration.t_stamp.min() and
            calibration.t_stamp.max() < test.t_stamp.min()
        ):
            raise ValueError('Declared sessions must be nonempty and chronological')
    elif protocol == "pre_attack":
        attacks = data.loc[data.y_true == 1, "t_stamp"]
        if attacks.empty:
            raise ValueError("Pre-attack protocol requires attack labels")
        first_attack = attacks.min()
        baseline = data[data.t_stamp < first_attack]
        if len(baseline) < 40:
            raise ValueError("Insufficient pre-attack baseline")
        boundary = baseline.iloc[int(len(baseline) * 0.8)].t_stamp
        train = baseline[baseline.t_stamp < boundary]
        calibration = baseline[baseline.t_stamp >= boundary]
        test = data[data.t_stamp >= first_attack]
    elif protocol == "chronological":
        times = data.t_stamp.drop_duplicates().to_list()
        if len(times) < 40:
            raise ValueError("Insufficient distinct timestamps")
        train_end, calibration_end = times[int(len(times)*0.6)], times[int(len(times)*0.8)]
        train = data[data.t_stamp < train_end]
        calibration = data[(data.t_stamp >= train_end) & (data.t_stamp < calibration_end)]
        test = data[data.t_stamp >= calibration_end]
    else:
        raise ValueError("Unknown evaluation protocol")
    train = train[train.y_true == 0]
    calibration = calibration[calibration.y_true == 0]
    if len(train) < 31 or len(calibration) < 10 or test.empty:
        raise ValueError("Need >=31 training-normal and >=10 calibration-normal samples plus a test set")
    return train, calibration, test


def train_candidate(data, features, source, protocol="chronological", target_fpr=0.01):
    if not 0 < target_fpr < 1:
        raise ValueError("Target false-positive rate must be between zero and one")
    train, calibration, test = temporal_split(data, protocol)
    if source == 'gateway-window':
        if protocol != 'declared_sessions' or list(features) != GATEWAY_WINDOW_FEATURES:
            raise ValueError('gateway-window requires its measured feature schema and declared sessions')
    def matrix(frame):
        values = frame[features].to_numpy(dtype=float)
        if not np.isfinite(values).all():
            raise ValueError("Features must be finite; missing readings are not zero")
        return values
    scaler = StandardScaler().fit(matrix(train))
    scaled = scaler.transform(matrix(train))
    isolation = IsolationForest(n_estimators=100, random_state=42, n_jobs=1).fit(scaled)
    lof = LocalOutlierFactor(n_neighbors=30, novelty=True, n_jobs=1).fit(scaled)
    mean, std = scaled.mean(axis=0), scaled.std(axis=0)
    # Fit score references on training only; calibration is reserved for threshold.
    cal_scaled = scaled
    references = {"if": np.sort(-isolation.decision_function(cal_scaled)),
        "lof": np.sort(-lof.decision_function(cal_scaled)),
        "z": np.sort(np.max(np.abs((cal_scaled - mean)/(std + 1e-6)), axis=1))}
    tail_scales = {name: max(float(np.std(values)), 1e-6)
                   for name, values in references.items()}
    models = {"tail_scales": tail_scales, "scoring_version": SCORING_VERSION, "feature_order": list(features),
        "feature_source": source, "scaler": scaler, "isolation_forest": isolation,
        "lof": lof, "normal_mean": mean, "normal_std": std, "calibration": references,
        "threshold": 1.0,
        "training_info": {"sklearn_version": sklearn.__version__, "protocol": protocol,
            "samples": len(train), "calibration_samples": len(calibration), "target_fpr": target_fpr,
            "train_end": train.t_stamp.max().isoformat(),
            "calibration_start": calibration.t_stamp.min().isoformat(),
            "calibration_end": calibration.t_stamp.max().isoformat()}}
    if source in ('swat-stage1', 'swat-process', 'gateway-window'):
        # A historical model needs a stated operating point for the simulated
        # plant. Derive it from training normals only, never held-out rows.
        models['training_info']['normal_reference'] = {
            name: float(train[name].median()) for name in
            (GATEWAY_WINDOW_FEATURES[:6] if source == 'gateway-window' else features)
        }
    if source == 'gateway-window':
        models['training_info']['window_seconds'] = WINDOW_SECONDS
        models['training_info']['window_scope'] = 'per_source_modbus_request'
        models['training_info']['train_sessions'] = sorted(train.session_id.unique().tolist())
        models['training_info']['calibration_sessions'] = sorted(calibration.session_id.unique().tolist())
        models['training_info']['test_sessions'] = sorted(test.session_id.unique().tolist())
    # Learn discrete support from training normals only, never evaluation labels.
    models['normal_support'] = ({name: sorted(train[name].unique().astype(float).tolist())
        for name in ('p101', 'p201', 'p203', 'p301', 'mv101', 'mv201')}
        if source == 'native-twin' else {})
    for name, values in models['normal_support'].items():
        if not calibration[name].isin(values).all():
            raise ValueError(f'Normal calibration contains unseen {name} values; expand normal training coverage')
    detector = RealTimeAnomalyDetector()
    detector.tail_scales = tail_scales
    detector.normal_support = models['normal_support']
    detector.FEATURE_ORDER = list(features)
    for attribute in ("scaler", "isolation_forest", "lof", "normal_mean", "normal_std", "calibration"):
        setattr(detector, attribute, models[attribute])
    calibration_scores = np.sort(detector.score_samples(matrix(calibration)))
    # Conservative order statistic: interpolation can put threshold below the
    # largest normal score even when the requested tail has fewer than one sample.
    rank = int(np.ceil((len(calibration_scores) + 1) * (1 - target_fpr)))
    threshold = float(calibration_scores[min(rank, len(calibration_scores)) - 1])
    models['training_info']['calibration_resolution'] = 1 / (len(calibration_scores) + 1)
    models['training_info']['target_fpr_supported'] = rank <= len(calibration_scores)
    models["threshold"] = threshold
    detector.threshold = threshold
    test_scores = detector.score_samples(matrix(test))
    report = {"scoring_version": SCORING_VERSION, "feature_source": source,
        "runtime_sklearn": sklearn.__version__, "protocol": protocol,
        "split": {"train_normal": len(train), "calibration_normal": len(calibration),
            "test": len(test), "test_normal": int((test.y_true==0).sum()),
            "test_attack": int((test.y_true==1).sum()), "test_start": test.t_stamp.min().isoformat()},
        "calibration_resolution": models['training_info']['calibration_resolution'],
        "target_fpr_supported": models['training_info']['target_fpr_supported'],
        "calibration": metrics(calibration.y_true, detector.score_samples(matrix(calibration)), threshold),
        "held_out": metrics(test.y_true, test_scores, threshold),
        "ensemble_only_held_out": metrics(test.y_true,
            detector.score_samples(matrix(test), include_support=False), threshold),
        "limitations": ["No threshold selected from test labels; this is not a deployment acceptance gate.",
            "A single dataset can contain temporal drift and correlated neighboring samples.",
            "Actuator novelty is a normal-support check, not proof of malicious intent.",
            "Tail scales are fitted on training normals only; continuous anomaly sensitivity needs independent evaluation.",
            "SWaT models require SWaT sensor values, not unrelated Twin sensor substitutions."]}
    if source == 'swat-aligned':
        report['limitations'].append(
            'Timestamp-aligned CSV aggregates lack packet-level Modbus attribution and differ from per-source gateway windows.')
    if source == 'gateway-window':
        report['limitations'].append(
            'Gateway sessions are simulated Twin observations; evaluate independent sessions and detection delay before enforcement.')
    return models, report

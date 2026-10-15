"""Feature contract for paired Twin state and gateway request windows.

These are gateway measurements, not substitutes for the SWaT CSV's
plant-wide network aggregates. One sample is scored on every request using
that source IP's trailing 60 seconds of complete Modbus request frames.
"""

import math

from research_state_profile import RESEARCH_PROCESS_FEATURES, SWAT_AGGREGATE_FEATURES

WINDOW_SECONDS = 60.0
NETWORK_FEATURES = SWAT_AGGREGATE_FEATURES
GATEWAY_WINDOW_FEATURES = [*RESEARCH_PROCESS_FEATURES, *NETWORK_FEATURES]


def features_from_event(event):
    """Accept only explicitly measured, internally consistent gateway rows."""
    detection = event.get("detection", {})
    network = event.get("network", {})
    statistics = event.get("network_statistics", {})
    process = event.get("process", {})
    if detection.get("window_seconds") != WINDOW_SECONDS:
        raise ValueError("gateway-window requires a 60-second request window")
    if not network.get("src_ip") or not network.get("dst_ip"):
        raise ValueError("gateway-window requires observed source and destination")
    if statistics.get("unique_src_ips") != 1:
        raise ValueError("gateway-window requires one source IP per window")
    count = statistics.get("packet_count")
    size = statistics.get("total_bytes")
    if not isinstance(count, (int, float)) or count < 1 or count != detection.get("window_packet_count"):
        raise ValueError("gateway-window packet count does not match the recorded window")
    if not isinstance(size, (int, float)) or size < 0:
        raise ValueError("gateway-window requires measured request bytes")
    if not math.isclose(statistics.get("packets_per_sec", float("nan")), count / WINDOW_SECONDS,
                        rel_tol=1e-6, abs_tol=1e-9):
        raise ValueError("gateway-window packet rate does not match the 60-second count")
    if not math.isclose(statistics.get("bytes_per_sec", float("nan")), size / WINDOW_SECONDS,
                        rel_tol=1e-6, abs_tol=1e-9):
        raise ValueError("gateway-window byte rate does not match the 60-second count")
    observed = {**process, **statistics}
    missing = set(GATEWAY_WINDOW_FEATURES) - set(observed)
    if missing:
        raise ValueError(f"gateway-window missing measured features: {sorted(missing)}")
    values = {name: float(observed[name]) for name in GATEWAY_WINDOW_FEATURES}
    if not all(math.isfinite(value) for value in values.values()):
        raise ValueError("gateway-window features must be finite")
    scored = event.get('model_features', {})
    if set(GATEWAY_WINDOW_FEATURES) - set(scored):
        raise ValueError('gateway-window requires the model features scored at runtime')
    if any(not math.isclose(values[name], float(scored[name]), rel_tol=1e-9, abs_tol=1e-9)
           for name in GATEWAY_WINDOW_FEATURES):
        raise ValueError('gateway-window process/network values differ from runtime model features')
    return values

"""Shared Stage 1 sensor schema for historical SWaT and the gateway Twin.

Network aggregates and Modbus command fields are deliberately excluded until
their runtime and historical measurement windows have been aligned.
"""

import numpy as np
import pandas as pd


RESEARCH_STATE_FEATURES = ["LIT101", "FIT101", "FIT201", "LIT301", "FIT301"]
RESEARCH_PROCESS_FEATURES = [*RESEARCH_STATE_FEATURES, "AIT202_pH"]
SWAT_AGGREGATE_FEATURES = [
    'packet_count', 'total_bytes', 'bytes_per_sec', 'packets_per_sec',
    'unique_src_ips', 'unique_dst_ips', 'unique_ip_pairs',
    'avg_packet_size', 'max_packet_size', 'packet_size_range',
    'bytes_per_packet', 'small_packets_count',
]
SWAT_ALIGNED_FEATURES = [*RESEARCH_PROCESS_FEATURES, *SWAT_AGGREGATE_FEATURES]

SWAT_COLUMNS = {
    "LIT101.Pv": "LIT101",
    "FIT101.Pv": "FIT101",
    "FIT201.Pv": "FIT201",
    "LIT301.Pv": "LIT301",
    "FIT301.Pv": "FIT301",
}
SWAT_PROCESS_COLUMNS = {**SWAT_COLUMNS, "AIT202.Pv": "AIT202_pH"}


def prepare_swat_stage1(data: pd.DataFrame) -> pd.DataFrame:
    """Select only measurements with an explicit Twin name/unit counterpart."""
    required = {"t_stamp", "y_true", *SWAT_COLUMNS}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"Missing SWaT Stage 1 columns: {sorted(missing)}")
    prepared = data[["t_stamp", "y_true", *SWAT_COLUMNS]].rename(
        columns=SWAT_COLUMNS
    ).copy()
    prepared[RESEARCH_STATE_FEATURES] = prepared[RESEARCH_STATE_FEATURES].apply(
        pd.to_numeric, errors="raise"
    )
    if not np.isfinite(prepared[RESEARCH_STATE_FEATURES].to_numpy(dtype=float)).all():
        raise ValueError("SWaT Stage 1 features must be finite")
    return prepared


def prepare_swat_process(data: pd.DataFrame) -> pd.DataFrame:
    """Add the Stage 2 pH sensor affected by the Twin's dosing pump."""
    prepared = prepare_swat_stage1(data)
    if 'AIT202.Pv' not in data:
        raise ValueError('Missing SWaT pH column: AIT202.Pv')
    prepared['AIT202_pH'] = pd.to_numeric(data['AIT202.Pv'], errors='raise')
    if not np.isfinite(prepared['AIT202_pH'].to_numpy(dtype=float)).all():
        raise ValueError('SWaT pH readings must be finite')
    return prepared


def prepare_swat_aligned(data: pd.DataFrame) -> pd.DataFrame:
    """Keep timestamp-aligned process and network CSV columns for offline use.

    The network values summarize the historical capture, not one source IP's
    gateway requests. The resulting artifact is deliberately not runnable in
    the Modbus gateway.
    """
    prepared = prepare_swat_process(data)
    missing = set(SWAT_AGGREGATE_FEATURES) - set(data)
    if missing:
        raise ValueError(f'Missing aligned SWaT network columns: {sorted(missing)}')
    prepared[SWAT_AGGREGATE_FEATURES] = data[SWAT_AGGREGATE_FEATURES].apply(
        pd.to_numeric, errors='raise')
    if not np.isfinite(prepared[SWAT_ALIGNED_FEATURES].to_numpy(dtype=float)).all():
        raise ValueError('Aligned SWaT features must be finite')
    return prepared


def initialize_twin_from_training_reference(twin, reference: dict) -> None:
    """Place the simulated plant near the historical training operating point."""
    if set(reference) not in (set(RESEARCH_STATE_FEATURES), set(RESEARCH_PROCESS_FEATURES)):
        raise ValueError("Incomplete SWaT process training reference")
    if any(not np.isfinite(value) or value < 0 for value in reference.values()):
        raise ValueError("Invalid SWaT Stage 1 training reference")
    state = twin.state
    for sensor in reference:
        setattr(state, sensor.lower(), float(reference[sensor]))
    if state.lit101 > twin.params.max_level_mm['lit101'] or state.lit301 > twin.params.max_level_mm['lit301']:
        raise ValueError("Historical levels exceed Twin capacity")
    # FIT101 measures MV101 inlet flow; FIT201 measures P101 outlet flow.
    # These binary states seed the simulator; later steps follow its equations.
    state.mv101 = int(state.fit101 > 0)
    state.mv201 = int(state.fit301 > 0)
    state.p101 = int(state.fit201 > 0)

"""Optional simulation safety/measurement guards, separate from ML scoring.

The 60-second horizon and measurement tolerances are declared lab policy, not
values fitted against attack labels. Real sensor uncertainty and timing must
be calibrated before using this policy with physical hardware.
"""
from copy import deepcopy
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Stage1Guard:
    forecast_seconds: float = 60.
    level_tolerance_mm: float = 5.
    flow_tolerance_m3h: float = .1

    def __post_init__(self):
        if (not 0 < self.forecast_seconds <= 300
                or not math.isfinite(self.level_tolerance_mm) or self.level_tolerance_mm <= 0
                or not math.isfinite(self.flow_tolerance_m3h) or self.flow_tolerance_m3h <= 0):
            raise ValueError('Invalid Stage-1 guard policy')

    def measurement_issues(self, predicted, measured):
        issues = {}
        for name, tolerance in [('LIT101', self.level_tolerance_mm), ('FIT101', self.flow_tolerance_m3h)]:
            if name in measured and name in predicted:
                difference = abs(measured[name] - predicted[name])
                if difference > tolerance:
                    issues[name] = {'predicted': predicted[name], 'measured': measured[name],
                                    'absolute_difference': difference, 'tolerance': tolerance}
        return issues

    def forecast(self, twin, actuator, value, detector):
        if twin.params.stage1_topology != 'swat_stage1':
            raise ValueError('Stage-1 guard requires the isolated Stage-1 plant')
        ticks = math.ceil(self.forecast_seconds / twin.params.dt_seconds)
        scores, spills = [], []
        for setting in (value, 1 - value):
            candidate = deepcopy(twin)
            candidate.apply_actions({actuator: setting})
            for _ in range(ticks):
                candidate.step()
            scores.append(detector.predict(candidate.snapshot()).ensemble_score)
            spills.append(candidate.state.stage1_spill_m3 - twin.state.stage1_spill_m3)
        return {'forecast_seconds': ticks * twin.params.dt_seconds,
                'forecast_score': scores[0], 'alternative_forecast_score': scores[1],
                'forecast_spill_m3': spills[0], 'alternative_forecast_spill_m3': spills[1]}

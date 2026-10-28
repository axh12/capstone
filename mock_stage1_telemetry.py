"""Lab-only injection at the existing read-only Stage-1 telemetry boundary.

Overrides affect the Twin's observed inputs, never the independent mock plant,
model, labels or decision engine. This is not a network sensor-write protocol.
"""


class MockStage1TelemetrySource:
    def __init__(self, scada, overrides=None):
        self.scada = scada
        self.overrides = dict(overrides or {})
        if not set(self.overrides) <= {'LIT101', 'FIT101'}:
            raise ValueError('Only Stage-1 sensor readings may be overridden')

    def read_state(self):
        with self.scada.lock:
            truth = self.scada.plant.snapshot()
        return {**{name: truth[name] for name in ('LIT101', 'FIT101')}, **self.overrides}

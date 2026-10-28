# SWaT Stage 1 mock pipeline

This mode contains only LIT101, FIT101, MV101, P101 and P102. Later-stage
levels, chemistry, dosing pumps and network aggregate features are excluded
from the detector. The older `swat-stage1` profile includes other stages;
the strict profile is named `swat-stage1-only`.

The mock is a separate simulated plant initialized from the same Stage-1
training reference as the Twin. Only writes actually delivered downstream
advance it. Blocked requests do not reach it. An explicit lab safety hook can
close MV101 and stop both transfer pumps without recording a forwarded request.

| Register | Meaning | Encoding |
| --- | --- | --- |
| 1 | LIT101 | Whole millimetres, legacy |
| 10 | FIT101 | Whole m³/h, legacy |
| 100 | LIT101 | Millimetres × 10 |
| 110 | FIT101 | m³/h × 1000 |
| 20 | P101 | 0 off, 1 on |
| 24 | P102 | 0 off, 1 on |
| 30 | MV101 | 0 closed, 1 open |

Unsupported stage registers return Modbus exception 02. Blocked writes and reads
return exception 04; blocked reads do not return untrusted Twin sensor values.
SWaT CSV actuator states use 2 for running/open and 1 for stopped/
closed; the mock's binary commands use 1 and 0 respectively. They are different
encodings, not a replay of historical packet addresses.

## Reproduce

```sh
dt-venv/bin/python validate_detector.py --profile swat-stage1-only \
  --output-dir validation/swat-stage1/model
dt-venv/bin/python swat_mock_profile.py
dt-venv/bin/python evaluate_mock_scada.py \
  --model validation/swat-stage1/model/detector_candidate.pkl \
  --swat-profile validation/swat-stage1/profile.json \
  --output-dir validation/swat-stage1/end-to-end --steps 80 --repeats 2
dt-venv/bin/python run_mock_lab.py --plant-topology swat_stage1 \
  --model validation/swat-stage1/model/detector_candidate.pkl \
  --swat-profile validation/swat-stage1/profile.json \
  --rules-file validation/swat-stage1/live/snort.rules \
  --telemetry-file validation/swat-stage1/live/telemetry.jsonl
```

Physics parameters use chronological training-normal rows only. Nominal inlet
flow comes from steady filling with both pumps off. Effective tank area is
estimated from inlet flow and level rise; P101 capacity comes from steady
draining with the inlet closed. P102 is assumed to have equal capacity. Only
contiguous one-second readings with stable actuator states enter those fits.
Calibration and test rows do not fit the physics or training reference.

The ensemble uses LIT101 and FIT101 only. Its threshold is selected on separate
normal calibration data. The historical CSV's attack labels cover the whole
plant, so offline metrics with these labels are not Stage-1 attack accuracy.

## Local evaluation meaning

The six scenarios cover reads, normal filling, P101 transfer, P102 standby
operation, forced filling near the training-normal 99th level percentile,
and forced draining near its 1st percentile. Every episode starts fresh; labels
are declared before inference and include lead-in commands. A stress episode
means sustained forcing beyond the historical normal operating envelope,
not a verified real-world attack or physical damage threshold.

One accepted write advances one simulated second. Reads do not advance time.
The matrix compares scenario intent with the final gateway ALLOW/BLOCK decision;
separate receipt checks verify that only ALLOW requests reach mock SCADA.
Repeated seeded episodes are correlated and do not establish general accuracy.
The prior multi-stage dosing benchmark is a different experiment.

This is a Stage-1 simulation with empirical normal calibration. It does not
reproduce the full SWaT PLC, raw packet captures, physical process or pfSense.

## Longer detection and exact-replay regression

The 80-request boundary-start benchmark above does not exercise the successful
longer normal-start draining sequence. Run that sequence separately, retaining
every malicious request in the primary confusion matrix:

```sh
dt-venv/bin/python -m unittest discover -s tests
dt-venv/bin/python evaluate_stage1_regression.py \
  --output validation/stage1-regression-NEW-RUN --episodes 3
```

Use a new output directory for each run. Each fresh episode sends a benign
P101 OFF packet, up to 400 malicious forcing requests until the first block,
the byte-identical rejected packet again, and the byte-identical benign packet
again. The rule file must contain the P101 ON drop signature before replay.
Every decision is checked against actual mock-SCADA receipt and the wire reply.
The rule file must remain unchanged across replay, and recovery must still pass.

An ALLOW for a malicious lead-in counts as FN. The first attributed BLOCK and
each blocked malicious replay count as TP. These replay TPs measure learned
gateway enforcement, not fresh independent ML detection. `report.json` includes
phase-specific counts and first-block delays. `confusion-matrix.svg` contains
all requests. `post-attribution-confusion-matrix.svg` contains only malicious
replay and benign-after checks and is explicitly conditional on attribution.
It must not replace the full matrix or the older benchmark.

The generated Snort rule and gateway quarantine use the same command signature,
but this local regression does not run a Snort engine or install rules on pfSense.
Its TCP servers use isolated ephemeral loopback ports. Validating a deployed
firewall drop requires a separate test on the actual configured network path.

## Overflow and sensor-falsification regression

```sh
dt-venv/bin/python evaluate_stage1_threats.py \
  --output validation/stage1-expanded-NEW-RUN --with-draining
```

This additionally tests sustained MV101-open commands from the normal operating
point and from 1198 mm, just below the simulation's 1200 mm capacity. The mock
now records cumulative spilled volume independently of the detector. Its open
inlet continues flowing at capacity; level clamping must not silently simulate
an automatic valve closure. Spilled volume is excluded from detector inputs.

Sensor falsification is injected through a lab-only implementation of the
existing Stage-1 read-only connector. The source overrides LIT101 or FIT101
without changing the independent mock plant. Cases include low/high level,
high flow, persistent low level, and subtle within-range changes. Each is
triggered by a real TCP read through the gateway. Reports separately record
detector observations, actual mock measurements, anomaly alarms, forwarding,
and returned sensor values. This models a compromised telemetry source; it
does not add a remotely writable sensor API or claim a captured network attack.

FC06 attempts to write sensor registers 1, 10, 100 and 110 are also checked.
They are protocol-permission rejections, not ML detections, and are excluded
from the detector confusion matrix. Sensor-only alarms do not generate an
unjustified command-specific Snort rule. `--with-draining` adds the earlier
normal-start draining, rule-generation, exact-replay and benign-recovery
sequence to the same primary matrix, including every allowed attack lead-in.

The initial overflow/sensor run is preserved under
`validation/stage1-threats-20261028`. It found that FC03 BLOCK responses still
contained a forged Twin reading. The updated gateway returns Modbus exception
04 instead. The rerun is preserved separately; detector and threshold were
not adjusted to make the cases pass. The previously running listener needs a
restart before it loads this code change.

## Predictive Stage-1 guards

`--stage1-guards` enables a hybrid policy in addition to the unchanged ML model:

- Simulate the requested and opposite actuator settings over 60 seconds. Attribute
  a forecast alarm only when the requested setting crosses the model threshold
  and the opposite setting does not.
- Block an actuator setting that predicts spilled volume when its opposite does
  not, even if both current ML scores are already anomalous.
- Check fresh sensor observations against the preceding predicted Twin state.
  Residuals above 5 mm or 0.1 m3/h reject the observation. The Twin rolls back to
  its preceding trusted state and the read returns an error. A sensor residual
  does not create a rule for an unrelated command.

The 60-second horizon and residual tolerances are explicit lab settings, not
learned sensor-accuracy bounds or verified physical safety parameters. Slow
drift and changes within tolerance remain possible. A forecast assumes that
the actuator setting persists for the horizon.

Reproduce the comparison without changing the baseline labels, bytes, ordering,
initial conditions, model or threshold:

```sh
dt-venv/bin/python compare_stage1_guards.py \
  --baseline validation/stage1-expanded-threats-20261028 \
  --output validation/stage1-guards-NEW-RUN
```

All 313 baseline requests are replayed, including attacks after an earlier new
block. The matrix does not shrink by stopping sooner. On the development traces,
FN fell from 297 to 225, TP rose from 10 to 82, and FP remained 2. Near-capacity
spill fell from 11.88 litres to zero; the first draining block moved from request
284 to 225. This is a hybrid-policy development regression after inspecting the
failures, not an untouched validation result or an ML-only accuracy improvement.

Start a fresh demo session with the guarded policy:

```sh
dt-venv/bin/python run_stage1_demo_server.py \
  --listen-host 192.168.58.105 --stage1-guards
```

The launcher prints `HYBRID GUARDS` so screenshots distinguish this policy from
the previous ML-only demo. Retain the older matrices when reporting the change.

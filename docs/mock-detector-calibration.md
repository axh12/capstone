# Mock Twin detector calibration

The historical SWaT process model and the simplified Twin have different
normal operating distributions. Historical validation metrics do not establish
the accuracy of local Modbus decisions. The original eight-step mock benchmark
produced TN=40, FP=40, FN=80, TP=0 across 160 transactions.

`calibrate_mock_twin.py` creates a separate simulation-only model using normal
Twin trajectories. It includes legitimate pump and valve switching, varying
starting levels, pH and independent random seeds. Entire chronological sessions
are separated into 2,160 training, 720 calibration and 720 normal test readings.
The 1% target false-positive threshold uses normal calibration readings only;
attack scenarios do not choose the threshold. The historical model is preserved.

```sh
dt-venv/bin/python calibrate_mock_twin.py
dt-venv/bin/python evaluate_mock_scada.py \
  --model validation/twin-calibrated/detector_candidate.pkl \
  --output-dir validation/mock-scada-twin-calibrated --repeats 5
```

On the unchanged 160-transaction test the candidate produced TN=80, FP=0,
FN=80, TP=0. Accuracy increased from 25% to 50%, but attack recall remains zero.
This removes false alarms in these scenarios; it does not establish effective
attack detection or safety. The synthetic operating ranges are assumptions,
not physical plant limits or a representative real-world dataset.

The benchmark's pump-on attack can request an already normal actuator state.
A process-only model cannot distinguish identical states by malicious intent.
Eight dosing steps may also precede a detectable process change. Preserve those
misses in the original confusion matrix rather than changing labels or injecting
a fixed register blacklist to improve its score.

Use a separately reported longer experiment to measure detection delay:

```sh
dt-venv/bin/python evaluate_mock_scada.py \
  --model validation/twin-calibrated/detector_candidate.pkl \
  --output-dir validation/mock-scada-twin-long --repeats 2 --steps 80
```

Reports include per-scenario blocking counts and the first blocked step of each
episode. Longer episodes change the benchmark; compare models with identical
episode lengths and report both results. Mock receipt checks validate forwarding,
not the correctness of the detector's verdict. This experiment excludes pfSense
and physical hardware. Independent representative normal and harmful sessions
are required before promoting this candidate to enforcement.

## Candidate decision: do not promote

The matched 80-step experiment (two repeats, 640 transactions per model)
exposed a sensitivity regression:

| Model | TN | FP | FN | TP | First dosing block |
| --- | ---: | ---: | ---: | ---: | --- |
| Historical SWaT | 160 | 160 | 224 | 96 | Step 33 in both episodes |
| Twin-calibrated candidate | 320 | 0 | 320 | 0 | None within 80 steps |

The candidate's normal-only threshold was approximately 0.9943. The combined
bounded ensemble score remained below it during dosing, even as simulated pH
fell to approximately 6.11. Broad normal control variation and a single global
threshold masked this process deviation. Normal-only validation is insufficient
to accept a detector: independent positive scenarios and delay measurements
must also pass. This candidate was not installed in the running gateway.

Next experiments should evaluate process-specific residuals or conditional
models that distinguish legitimate operating modes, with separate development
and untouched acceptance scenarios. Lowering a threshold against the displayed
attack results would make those scenarios development data, not held-out proof.

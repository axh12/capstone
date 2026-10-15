# Native detector revision

Normal actuator values are learned from training-normal samples only. A value outside that support yields novelty score 1 rather than being diluted by the ensemble average. This detects unknown operating states, not malicious intent. Legitimate states missing from training can be blocked. Retrain artifacts to enable this optional support check; existing artifacts retain their previous behavior.

Final SEM results now include detector feature deviations. Telemetry records score, threshold, anomaly flag, type and novelty evidence. The early candidate signature log precedes detection and is not the final result.

On the existing 300 observations: old TP=1 FN=29 FP=6 TN=24; revised TP=30 FN=0 FP=6 TN=24. Threshold unchanged at 0.9568032786885245. These samples informed diagnosis, so this is a regression result, not independent validation. Baseline is repetitive and abnormal session restarted the Twin. Collect fresh representative normal sessions and independent abnormal sessions before deployment.

Remaining: 20% observed false positives; request-window traffic aggregation; native attack attribution beyond novelty; persistent anomalous state may produce signatures for subsequent benign commands. Automatic enforcement should remain disabled pending fresh validation.

Verification: 81 tests run, 73 passed, 8 skipped (PHP-dependent tests); Python compile check passed. Revised artifact/report: validation/native-revised/.

## Calibration and SEM follow-up

Score references now use training samples, reserving normal calibration samples exclusively for threshold selection. Threshold uses a conservative order statistic rather than interpolation. With 60 calibration normals, the nominal 1% target is below the attainable rank resolution (1/61); reports explicitly mark it unsupported. New artifacts are in validation/native-calibrated; prior artifacts remain unchanged.

Regression on existing observations: TP=30 FN=0 FP=0 TN=30. This dataset informed development, so these results are not independent validation or general zero-day accuracy. Detection of these abnormal writes is driven by learned actuator support. Runtime telemetry separately exposes ensemble_only_score and detection_basis. Rank-based continuous scores still saturate and require independent evaluation.

SEM process-novelty signatures now retain only writes matching an anomalous actuator and its value. An unrelated command in an already anomalous state cannot produce a new command-specific rule. Early SEM logs are labeled candidate-before-detection.

Verification before final telemetry additions: 85 tests, 77 passed, 8 PHP-dependent tests skipped. Added regression tests cover training-only score references, finite sample calibration and signature attribution.

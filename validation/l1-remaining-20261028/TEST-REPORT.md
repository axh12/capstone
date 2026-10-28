# Expanded L1 SCADA acceptance report

145 cases: 108 PASS, 37 FAIL, 0 execution errors.

Security matrix (118 named tests): TN=37, FP=4, FN=24, TP=53.

Robustness checks: 27 total, 18 passed, 9 failed.

Each named case counts once; its request count does not determine its matrix weight.
Robustness/fault cases are included in the overall pass/fail total but excluded from the binary security matrix.

| ID | Area | Category | Test | Result | Observations |
| --- | --- | --- | --- | --- | --- |
| L1-001 | normal | benign | Normal filling at 550 mm | PASS | {} |
| L1-002 | normal | benign | Normal filling at 700 mm | FAIL | {} |
| L1-003 | normal | benign | Normal filling at 800 mm | FAIL | {} |
| L1-004 | normal | benign | Normal P101 transfer at 550 mm | PASS | {} |
| L1-005 | normal | benign | Normal P101 transfer at 740 mm | PASS | {} |
| L1-006 | normal | benign | Normal P101 transfer at 820 mm | FAIL | {} |
| L1-007 | normal | benign | Normal P102 transfer at 550 mm | PASS | {} |
| L1-008 | normal | benign | Normal P102 transfer at 740 mm | PASS | {} |
| L1-009 | normal | benign | Normal P102 transfer at 820 mm | FAIL | {} |
| L1-010 | normal | benign | Changeover register 20 to 24 | PASS | {} |
| L1-011 | normal | benign | Changeover register 24 to 20 | PASS | {} |
| L1-012 | normal | benign | Safe rapid pump reversals | PASS | {} |
| L1-013 | process | malicious | Overflow near capacity with 0 running pumps | PASS | {"first_block_step": 1, "detected": true, "prevention_passed": true, "minimum_level_mm": 1198.0, "spill_m3": 0.0, "low_level_limit_mm": null, "replay_blocked": true} |
| L1-014 | process | malicious | Overflow near capacity with 1 running pumps | PASS | {"first_block_step": 1, "detected": true, "prevention_passed": true, "minimum_level_mm": 1198.0, "spill_m3": 0.0, "low_level_limit_mm": null, "replay_blocked": true} |
| L1-015 | process | malicious | Overflow near capacity with 2 running pumps | PASS | {"first_block_step": 1, "detected": true, "prevention_passed": true, "minimum_level_mm": 1198.0, "spill_m3": 0.0, "low_level_limit_mm": null, "replay_blocked": true} |
| L1-016 | boundary | malicious | Inlet opening at capacity boundary 1199.9 mm | PASS | {"first_block_step": 1, "detected": true, "prevention_passed": true, "minimum_level_mm": 1199.9, "spill_m3": 0.0, "low_level_limit_mm": null, "replay_blocked": true} |
| L1-017 | boundary | benign | Safe inlet closure at 1199.9 mm | PASS | {} |
| L1-018 | boundary | malicious | Inlet opening at capacity boundary 1200 mm | PASS | {"first_block_step": 1, "detected": true, "prevention_passed": true, "minimum_level_mm": 1200.0, "spill_m3": 0.0, "low_level_limit_mm": null, "replay_blocked": true} |
| L1-019 | boundary | benign | Safe inlet closure at 1200 mm | PASS | {} |
| L1-020 | process | malicious | Low-level forced register 20 ON at 99 mm | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 95.55, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-021 | process | malicious | Low-level forced register 20 ON at 100 mm | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 96.55, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-022 | process | malicious | Low-level forced register 20 ON at 101 mm | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 97.55, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-023 | process | malicious | Low-level forced register 24 ON at 99 mm | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 95.55, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-024 | process | malicious | Low-level forced register 24 ON at 100 mm | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 96.55, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-025 | process | malicious | Low-level forced register 24 ON at 101 mm | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 97.55, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-026 | process | malicious | Both pumps forced ON near low level | FAIL | {"detected": false, "prevention_passed": false, "minimum_level_mm": 94.09, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-027 | sensors | malicious | False low level | PASS | {"detected": true, "prevention_passed": true} |
| L1-028 | sensors | malicious | False high level | PASS | {"detected": true, "prevention_passed": true} |
| L1-029 | sensors | malicious | False high inlet flow | PASS | {"detected": true, "prevention_passed": true} |
| L1-030 | sensors | malicious | Subtle false level | PASS | {"detected": true, "prevention_passed": true} |
| L1-031 | sensors | malicious | Subtle false flow | FAIL | {"detected": false, "prevention_passed": false} |
| L1-032 | sensors | malicious | Persistent false level | PASS | {"detected": true, "prevention_passed": true} |
| L1-033 | sensors | malicious | Flow reported while inlet closed | PASS | {"detected": true, "prevention_passed": true} |
| L1-034 | sensors | malicious | Level jump without inlet flow | PASS | {"detected": true, "prevention_passed": true} |
| L1-035 | sensors | malicious | Slow bias LIT101 -2 per observation | FAIL | {"detected": false, "first_block_step": null, "final_observed": {"LIT101": 699.4, "FIT101": 0.0}, "actual": {"LIT101": 739.4, "FIT101": 0.0, "p101": 0, "p102": 0, "mv101": 0}} |
| L1-036 | sensors | malicious | Slow bias LIT101 +2 per observation | FAIL | {"detected": false, "first_block_step": null, "final_observed": {"LIT101": 779.4, "FIT101": 0.0}, "actual": {"LIT101": 739.4, "FIT101": 0.0, "p101": 0, "p102": 0, "mv101": 0}} |
| L1-037 | sensors | malicious | Slow bias FIT101 +0.02 per observation | FAIL | {"detected": false, "first_block_step": null, "final_observed": {"LIT101": 739.4, "FIT101": 0.4}, "actual": {"LIT101": 739.4, "FIT101": 0.0, "p101": 0, "p102": 0, "mv101": 0}} |
| L1-038 | sensors | malicious | Frozen level during pumping | FAIL | {"detected": false, "unrelated_command_blocked": false, "actual_level": 733.52, "twin_level": 740.0, "residual_after_sequence_mm": 6.480000000000018} |
| L1-039 | sensors | malicious | Frozen level during filling | PASS | {"detected": true, "unrelated_command_blocked": false, "actual_level": 613.54, "twin_level": 600.0, "residual_after_sequence_mm": 13.539999999999964} |
| L1-040 | sensors | malicious | Replay old level after plant changes | FAIL | {"detected": false, "unrelated_command_blocked": false, "actual_level": 733.52, "twin_level": 740.0, "residual_after_sequence_mm": 6.480000000000018} |
| L1-041 | sensors | malicious | Frozen flow after inlet closure | PASS | {"detected": true, "closing_allowed": true} |
| L1-042 | faults | robustness | Telemetry empty | FAIL | {"elapsed_seconds": 0.02236776199970336, "freshness_requirement_seconds": 0.1, "fail_closed": false} |
| L1-043 | faults | robustness | Telemetry partial | FAIL | {"elapsed_seconds": 0.023758416000418947, "freshness_requirement_seconds": 0.1, "fail_closed": false} |
| L1-044 | faults | robustness | Telemetry disconnected | PASS | {"elapsed_seconds": 0.0035700659991562134, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-045 | faults | robustness | Telemetry delayed | FAIL | {"elapsed_seconds": 0.2433724259990413, "freshness_requirement_seconds": 0.1, "fail_closed": false} |
| L1-046 | faults | robustness | Telemetry nonnumeric | PASS | {"elapsed_seconds": 0.0011215760005143238, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-047 | faults | robustness | Telemetry nan | PASS | {"elapsed_seconds": 0.0029948009996587643, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-048 | faults | robustness | Telemetry out_of_range | PASS | {"elapsed_seconds": 0.0019313239990879083, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-049 | boundary | benign | Level residual boundary 4.99 mm | PASS | {} |
| L1-050 | boundary | benign | Level residual boundary 5 mm | PASS | {} |
| L1-051 | boundary | malicious | Level residual boundary 5.01 mm | PASS | {"detected": true, "prevention_passed": true} |
| L1-052 | boundary | benign | Flow residual boundary 0.099 m3/h | PASS | {} |
| L1-053 | boundary | benign | Flow residual boundary 0.1 m3/h | PASS | {} |
| L1-054 | boundary | malicious | Flow residual boundary 0.101 m3/h | PASS | {"detected": true, "prevention_passed": true} |
| L1-055 | protocol | malicious | Modbus unsupported_function | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-056 | protocol | malicious | Modbus invalid_value | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-057 | protocol | malicious | Modbus sensor_write | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-058 | protocol | malicious | Modbus unknown_register | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-059 | protocol | malicious | Modbus zero_read_count | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-060 | protocol | malicious | Modbus excess_read_count | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-061 | protocol | malicious | Modbus other_stage_read | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-062 | protocol | malicious | Modbus bad_protocol | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-063 | protocol | malicious | Modbus bad_length | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-064 | protocol | malicious | Modbus truncated | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-065 | protocol | benign | Valid fragmented TCP request | PASS | {} |
| L1-066 | protocol | benign | Two requests on persistent TCP connection | PASS | {"requests": ["1f4000000006010600140000", "1f41000000060106001e0000"], "replies": ["1f4000000006010600140000", "1f41000000060106001e0000"], "forwarded": 2} |
| L1-067 | traffic | benign | Legitimate slow clients | PASS | {"requests": 4, "forwarded": 4, "model_or_guard_alarm": false, "source_windows_isolated": true, "max_response_seconds": 0.1400497249996988} |
| L1-068 | traffic | benign | Legitimate burst clients | PASS | {"requests": 20, "forwarded": 20, "model_or_guard_alarm": false, "source_windows_isolated": true, "max_response_seconds": 0.14456396199966548} |
| L1-069 | traffic | benign | Legitimate concurrent clients | PASS | {"requests": 20, "forwarded": 20, "model_or_guard_alarm": false, "source_windows_isolated": true, "max_response_seconds": 0.7760404320015368} |
| L1-070 | traffic | benign | Legitimate multiple_sources clients | PASS | {"requests": 4, "forwarded": 4, "model_or_guard_alarm": false, "source_windows_isolated": true, "max_response_seconds": 0.13700304600024538} |
| L1-071 | traffic | malicious | Declared malicious read burst | FAIL | {"requests": 20, "forwarded": 20, "model_or_guard_alarm": false, "source_windows_isolated": true, "max_response_seconds": 0.034305634999327594} |
| L1-072 | rules | malicious | Rule selectivity exact | PASS | {} |
| L1-073 | rules | benign | Rule selectivity different_value | PASS | {} |
| L1-074 | rules | benign | Rule selectivity different_register | PASS | {} |
| L1-075 | rules | malicious | Rule selectivity different_source | PASS | {} |
| L1-076 | recovery | benign | Genuine telemetry recovery after sensor alarm | PASS | {"forged_read_rejected": true, "genuine_read_allowed": true} |
| L1-077 | recovery | robustness | Normal request after gateway restart | PASS | {} |
| L1-078 | rules | malicious | Durable replay protection after restart | FAIL | {"rule_file_retained": true, "replay_blocked": false} |
| L1-079 | rules | robustness | Rule expiration and quarantine consistency | FAIL | {"rule_file_expired": true, "safe_command_allowed": false} |
| L1-080 | faults | robustness | Mock SCADA disconnect | PASS | {"state_rolled_back": true} |
| L1-081 | faults | robustness | Rule export filesystem failure | PASS | {"export_error_reported": true} |
| L1-082 | process | malicious | Sustained draining detection and recovery | PASS | {"first_block_step": 225, "early_allowed": 224, "detected": true, "first_packet_prevention": false, "rule_generated": true, "replay_blocked": true, "benign_after_allowed": true} |
| L1-083 | normal | benign | L1 register 1 readback | PASS | {"expected": 739, "returned": 739} |
| L1-084 | normal | benign | L1 register 10 readback | PASS | {"expected": 0, "returned": 0} |
| L1-085 | normal | benign | L1 register 100 readback | PASS | {"expected": 7394, "returned": 7394} |
| L1-086 | normal | benign | L1 register 110 readback | PASS | {"expected": 0, "returned": 0} |
| L1-087 | normal | benign | L1 register 20 readback | PASS | {"expected": 0, "returned": 0} |
| L1-088 | normal | benign | L1 register 24 readback | PASS | {"expected": 0, "returned": 0} |
| L1-089 | normal | benign | L1 register 30 readback | PASS | {"expected": 0, "returned": 0} |
| L1-090 | process | malicious | Empty/very-low tank pump 20 ON at 0 mm | FAIL | {"detected": false, "prevention_passed": true, "minimum_level_mm": 0.0, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-091 | process | malicious | Empty/very-low tank pump 24 ON at 0 mm | FAIL | {"detected": false, "prevention_passed": true, "minimum_level_mm": 0.0, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-092 | process | malicious | Empty/very-low tank pump 20 ON at 1 mm | FAIL | {"detected": false, "prevention_passed": true, "minimum_level_mm": 1.0, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-093 | process | malicious | Empty/very-low tank pump 24 ON at 1 mm | FAIL | {"detected": false, "prevention_passed": true, "minimum_level_mm": 1.0, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-094 | process | malicious | Empty/very-low tank pump 20 ON at 50 mm | FAIL | {"detected": false, "prevention_passed": true, "minimum_level_mm": 50.0, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-095 | process | malicious | Empty/very-low tank pump 24 ON at 50 mm | FAIL | {"detected": false, "prevention_passed": true, "minimum_level_mm": 50.0, "spill_m3": 0.0, "low_level_limit_mm": 100.0} |
| L1-096 | boundary | benign | Safe pump 20 OFF at 0 mm | PASS | {} |
| L1-097 | boundary | benign | Safe pump 24 OFF at 0 mm | PASS | {} |
| L1-098 | boundary | benign | Safe pump 20 OFF at 50 mm | PASS | {} |
| L1-099 | boundary | benign | Safe pump 24 OFF at 50 mm | PASS | {} |
| L1-100 | boundary | benign | Safe pump 20 OFF at 100 mm | PASS | {} |
| L1-101 | boundary | benign | Safe pump 24 OFF at 100 mm | PASS | {} |
| L1-102 | faults | robustness | Telemetry missing_flow | FAIL | {"elapsed_seconds": 0.034297308999157394, "freshness_requirement_seconds": 0.1, "fail_closed": false} |
| L1-103 | faults | robustness | Telemetry null | PASS | {"elapsed_seconds": 0.0022372109997377265, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-104 | faults | robustness | Telemetry positive_infinity | PASS | {"elapsed_seconds": 0.0010828240010596346, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-105 | faults | robustness | Telemetry negative_infinity | PASS | {"elapsed_seconds": 0.0010660409989213804, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-106 | faults | robustness | Telemetry negative_level | PASS | {"elapsed_seconds": 0.0016982849992928095, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-107 | faults | robustness | Telemetry negative_flow | PASS | {"elapsed_seconds": 0.022585482998692896, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-108 | faults | robustness | Telemetry infinite_flow | PASS | {"elapsed_seconds": 0.0019372250008018455, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-109 | faults | robustness | Telemetry flow_string | PASS | {"elapsed_seconds": 0.001031585999953677, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-110 | faults | robustness | Telemetry boolean_level | PASS | {"elapsed_seconds": 0.0019301310003356775, "freshness_requirement_seconds": 0.1, "fail_closed": true} |
| L1-111 | recovery | robustness | Recovery after telemetry disconnected | PASS | {"fault_fail_closed": true, "recovered": true} |
| L1-112 | recovery | robustness | Recovery after telemetry nonnumeric | PASS | {"fault_fail_closed": true, "recovered": true} |
| L1-113 | recovery | robustness | Recovery after telemetry nan | PASS | {"fault_fail_closed": true, "recovered": true} |
| L1-114 | recovery | robustness | Recovery after telemetry missing_flow | FAIL | {"fault_fail_closed": false, "recovered": true} |
| L1-115 | protocol | malicious | Modbus fc0 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-116 | protocol | malicious | Modbus fc5 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-117 | protocol | malicious | Modbus fc15 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-118 | protocol | malicious | Modbus fc23 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-119 | protocol | malicious | Modbus fc255 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-120 | protocol | malicious | Modbus p102_value65535 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-121 | protocol | malicious | Modbus valve_value2 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-122 | protocol | malicious | Modbus legacy_level_write | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-123 | protocol | malicious | Modbus legacy_flow_write | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-124 | protocol | malicious | Modbus scaled_flow_write | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-125 | protocol | malicious | Modbus other_stage_write | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-126 | protocol | malicious | Modbus read_gap | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-127 | protocol | malicious | Modbus address65535 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-128 | protocol | malicious | Modbus length0 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-129 | protocol | malicious | Modbus length255 | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-130 | protocol | malicious | Modbus truncated_header | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-131 | protocol | malicious | Modbus short_pdu | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-132 | protocol | malicious | Modbus long_pdu | PASS | {"protocol_rejected": true, "valid_followup_allowed": true, "rejection_layer": "protocol validation; not ML"} |
| L1-133 | protocol | robustness | Unconfigured unit ID 0 | FAIL | {} |
| L1-134 | protocol | robustness | Unconfigured unit ID 2 | FAIL | {} |
| L1-135 | protocol | robustness | Unconfigured unit ID 255 | FAIL | {} |
| L1-136 | protocol | benign | Coalesced requests in one TCP send | PASS | {"requests": ["1fa400000006010600140000", "1fa5000000060106001e0000"], "replies": ["1fa400000006010600140000", "1fa5000000060106001e0000"], "forwarded": 2} |
| L1-137 | rules | malicious | Quarantined payload with changed transaction ID | PASS | {} |
| L1-138 | sensors | malicious | Small gradual bias FIT101 -0.02 | FAIL | {"detected": false, "first_block_step": null, "final_observed": {"LIT101": null, "FIT101": null}, "actual": {"LIT101": 739.4, "FIT101": 0.0, "p101": 0, "p102": 0, "mv101": 0}} |
| L1-139 | sensors | malicious | Small gradual bias LIT101 +0.5 | FAIL | {"detected": false, "first_block_step": null, "final_observed": {"LIT101": 749.4, "FIT101": 0.0}, "actual": {"LIT101": 739.4, "FIT101": 0.0, "p101": 0, "p102": 0, "mv101": 0}} |
| L1-140 | sensors | malicious | Small gradual bias LIT101 -0.5 | FAIL | {"detected": false, "first_block_step": null, "final_observed": {"LIT101": 729.4, "FIT101": 0.0}, "actual": {"LIT101": 739.4, "FIT101": 0.0, "p101": 0, "p102": 0, "mv101": 0}} |
| L1-141 | sensors | malicious | Combined sensor spoof {'LIT101': 700.0, 'FIT101': 2.0} | PASS | {"detected": true, "prevention_passed": true} |
| L1-142 | sensors | malicious | Combined sensor spoof {'LIT101': 740.0, 'FIT101': -0.101} | PASS | {"detected": true, "prevention_passed": true} |
| L1-143 | sensors | malicious | False normal telemetry concealing hazardous register 30 | PASS | {"prevented": true, "actual_level": 1199.9, "spill_m3": 0.0} |
| L1-144 | sensors | malicious | False normal telemetry concealing hazardous register 20 | PASS | {"prevented": true, "actual_level": 99.0, "spill_m3": 0.0} |
| L1-145 | sensors | malicious | False normal telemetry concealing hazardous register 24 | PASS | {"prevented": true, "actual_level": 99.0, "spill_m3": 0.0} |

## Matrix definition

- TN: benign acceptance test passed; FP: benign test failed.
- TP: malicious acceptance test passed its declared detection/prevention requirement; FN: malicious test failed.
- Protocol defenses are included as system controls, not ML performance.
- Delayed draining detection has its own explicit bounded criterion. Early requests are disclosed; prevention is not inferred.
- Execution errors are not counted as successful detections and are reported separately.

## Limitations

- Cases and criteria are written before the run. This is a development acceptance suite, not independently sampled validation.
- Local TCP servers and a simulated plant; no Kali, physical PLC or pfSense enforcement.
- One named security test counts once. Robustness/fault cases and execution errors are reported separately from the matrix.
- Matrix includes protocol-permission controls as system defense, not ML detections.
- A delayed-detection pass does not establish first-packet prevention; its early allowed count is reported.
- 100 mm low-level limit and 0.1 s freshness requirement are declared lab acceptance requirements, not plant-calibrated safety limits.
- Slow-client delays are short regressions; 20-request bursts and eight workers are not load-capacity benchmarks.
- The read-burst label declares stress intent; it is not proof of harmful DoS. Current process-only model has no network-rate input.
- Restart persistence and coherent expiry are desired security requirements; current gateway quarantine is in memory.
- No model scores or decisions are mocked; only sensor and I/O fault boundaries are injected.
- No production model, guard settings, firewall settings or existing live listener are modified.
- A matrix from this broader case population is not directly comparable to the earlier 15-case pass rate.

## Coverage not run

Not run: physical PLC/sensor/actuator faults, installed Snort/pfSense enforcement, Kali/VM reboot/network partitions, timestamp-authenticated telemetry replay, long-duration capacity/fuzzing, held-out attack captures and plant calibration. See docs/l1-comprehensive-testing.md.

See `COVERAGE.md` for the bounded coverage checklist and deployment exclusions.

# Expanded L1 SCADA acceptance suite

Run the software regression tests and a fresh isolated acceptance run:

```sh
dt-venv/bin/python -m unittest discover -s tests
dt-venv/bin/python evaluate_l1_suite.py \
  --output validation/l1-comprehensive-NEW-RUN
```

The suite writes its complete 145-case manifest and pass criteria before sending
requests. Each case gets an isolated gateway and independent mock plant, the
existing trained Stage-1 detector, and the unchanged hybrid guards. No model
prediction or enforcement decision is replaced. Sensor faults enter through
the telemetry connector; filesystem and connection failures enter at their
respective component boundaries. Existing live demo sessions are untouched.

## Coverage

- Normal filling at 550, 700 and 800 mm; P101 and P102 transfer at 550, 740 and
  820 mm; duty/standby changeover in both directions; safe rapid reversals.
- Near-capacity overflow with zero, one and two pumps running; valve opening
  and safe closure at 1199.9 and 1200 mm; forced low-level pumping with either
  pump and both pumps; bounded sustained draining and exact replay/recovery.
- Large and subtle level/flow spoofing; persistent spoofing; gradual positive
  and negative level bias; gradual flow bias; frozen level during pumping and
  filling; replayed old readings; frozen flow after a valve transition;
  measurements inconsistent with actuator/process state.
- Empty, partial, delayed, disconnected, nonnumeric, nonfinite and out-of-range
  telemetry. The lab freshness requirement is 0.1 seconds; it is a declared
  acceptance target, not a measured physical-device specification.
- Measurement residuals just below, at and above the 5 mm / 0.1 m3/h settings;
  low-level cases at 99, 100 and 101 mm. The 100 mm low-level oracle is a lab
  requirement; an already-low starting state is graded on further depletion.
- Unsupported function, invalid actuator value, sensor-register write, unknown
  register, invalid read counts, other-stage access, invalid protocol/length,
  truncated frames, valid fragmentation and multiple requests per connection.
- Short slow-client sequence, 20-request benign burst, eight-worker concurrency,
  multiple loopback source addresses and source-window isolation. A declared
  malicious read burst also measures the process-only model's network blind spot.
  These are functional regressions, not DoS proof or capacity benchmarks.
- Exact rule replay, changed value/register, replay from another source,
  telemetry recovery, gateway restart, desired durable replay protection,
  rule-expiry/quarantine consistency, downstream outage and rule-export failure.

## Reports and matrices

`TEST-REPORT.md` lists all 145 cases, expectations, PASS/FAIL/ERROR and observed
details. `report.json` includes area totals and case details. Each case directory
contains its outcome, wire responses and telemetry; malformed/parallel tests
also record their transport checks in the outcome details.

The main matrix counts **named security scenarios**, never packets:

- TN: benign test passed its acceptance requirement.
- FP: benign test failed, for example because a valid command was blocked.
- TP: malicious test passed its specified rejection/detection/prevention checks.
- FN: malicious test failed those checks.

There are 118 benign/malicious cases. Twenty-seven fault/robustness checks have separate
pass/fail totals and are excluded from the binary security matrix. Execution
errors are reported separately and never counted as successful detections.
Protocol-permission cases are included as system defenses, not ML detections;
the JSON report also provides a matrix excluding those cases.

Detection and prevention are separate observations where relevant. The bounded
draining test permits eventual detection within 300 commands; it explicitly
records its first blocked step, earlier allowed commands and first-packet
prevention result. Overflow/low-level tests require both blocking and the
independent physical oracle. A frozen-sensor test cannot pass solely because
an unrelated valid setup command was falsely blocked.

Restart durability and coherent expiry are desired hardening requirements.
The current gateway documents an in-memory quarantine; failing these new tests
does not imply that persistence had previously been implemented. The restart
tests actually rebuild the gateway component, not the Ubuntu VM.

The 145-case population differs from the earlier 15-case demonstration. Their
pass percentages must not be presented as directly comparable accuracy. These
are development acceptance results on a simplified plant, not independently
sampled real-world validation. Snort rules are generated locally; this suite
does not install them on pfSense or exercise Kali.

## Remaining-case expansion

The append-only expansion adds 63 cases, L1-083 through L1-145, while preserving
all original IDs, criteria and policy settings:

- Seven sensor/actuator register readbacks, checked against independent mock
  state, including fixed-point scaling and transaction identity.
- Both pumps forced ON at 0, 1 and 50 mm; safe pump OFF at 0, 50 and 100 mm.
- Missing flow, null/boolean level, positive/negative infinity, negative level,
  negative/infinite flow and nonnumeric flow; recovery after four sensor faults.
- More unsupported function codes, invalid P102/valve values, writes to legacy
  and scaled sensors, other-stage writes, reads across register gaps, maximum
  address, zero/oversized MBAP length, truncated header and short/long PDUs.
- Unconfigured unit IDs 0, 2 and 255. These are robustness checks against an
  explicitly declared single-unit lab requirement, not assumed ML attacks.
- Coalesced frames, a quarantined payload with changed transaction ID, smaller
  level biases and negative flow bias, combined sensor spoofing, and false
  normal readings concealing overflow or low-level pump commands.

## Coverage still requiring another environment or specification

This is a finite software acceptance checklist, not every possible L1 test.
The following are **not run** and are excluded from all pass/fail counts:

- Physical PLC/sensor/actuator faults: stuck valve/pump, failed relay, real
  calibration error, electrical signal loss and independently measured flow.
- Installed Snort rule parsing/reload and actual pfSense packet blocking,
  expiration and deployment rollback. Gateway-cache blocking is exercised;
  generating a rule file does not prove a firewall enforced it.
- A real Kali-to-Ubuntu VM network run, VM reboot, network partitions and link
  reconnection under the deployed routing/firewall configuration.
- Authenticated telemetry replay/stale timestamps and provenance: the current
  connector provides values without source timestamps or authentication.
- An approved multi-unit device policy, alternative Modbus function support,
  long-duration soak/capacity limits, exhaustive frame fuzzing and resource
  exhaustion. The three unit-ID tests declare the single-unit lab expectation.
- Independently held-out SWaT attack capture evaluation and calibration of
  plant-specific safety limits, sensor noise, latency and P102 capacity.

These require hardware, deployment access, data or explicit acceptance limits.
They must not be represented as completed tests in the updated report.

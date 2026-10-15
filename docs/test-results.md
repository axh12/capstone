# Offline test results

Run date: 10 October 2026. Interpreter: `dt-venv/bin/python`.

Command: `dt-venv/bin/python -m unittest discover -s tests -v`

Latest run: **80 test methods executed; all 80 passed**, including 8 PHP helper
tests using an isolated PHP runtime with stubbed pfSense APIs.
The four originally failing test methods now pass after the fixes below.

Additional tests cover calibrated score direction, batch invariance,
scalar/batch agreement, missing/nonfinite feature rejection, artifact/schema
and version checks, temporal split separation, independence from test labels,
native telemetry recording, incompatible gateway models, SSH deployment
validation/cleanup, and preservation of BLOCK after remote failure. The PHP
harness verifies custom-rule merging, SID conflicts, mode checks, inspection,
validation/reload rollback and idempotence. No real firewall is contacted.

PHP execution on another machine requires PHP CLI; those 8 harness tests
are skipped when it is absent. This run used a PHP package extracted under
`/tmp`, with `CAPSTONE_PHP` and `LD_LIBRARY_PATH` set. Loopback tests ran
outside the sandbox because socket binding is restricted inside it.

| Original defect | Original evidence | Resolution |
| --- | --- | --- |
| Empty Modbus command list | IndexError in `_finalize_telemetry` | Empty lists handled before indexing |
| Fractional actuator accepted | Validator accepts `p101=0.5` | Values must equal 0 or 1 without integer truncation |
| Invalid actuator types raise | None, text and list raise TypeError/ValueError | Conversion errors return a validation rejection |
| Unapproved candidate published | Both candidates appear in the rule file | Candidate generation isolated; only explicitly activated candidates enter the active manager |

Passing tests cover physics reproducibility/effects/bounds, state snapshots
and transitions, nonfinite sensor rejection, telemetry serialization/deltas,
packet feature statistics/reset/schema/order, controlled detector threshold
behavior and missing/unloaded artifacts, rule deduplication/expiration/discard,
normal/anomalous pipeline gating, inference failure, and mocked read-only
Stage 1 synchronization and connection/read errors.

Pipeline decision tests stub detector outputs and signature extraction. They
verify integration control flow, not real-model accuracy or packet decoding.
Twelve additional gateway tests use real loopback TCP connections to a mock
SCADA server. They verify normal forwarding and Twin state effects; first
and repeated anomalous writes never reaching SCADA; temporary drop-rule
generation; blocked reads; detector/SEM failures; upstream unavailability;
invalid actuator/register/protocol requests; fragmented and truncated frames;
multiple requests per connection; and unrelated normal traffic after an
anomaly. An additional lifecycle test verifies discarding a duplicate
candidate preserves a previously activated rule.

Stage 1 tests use a mock Modbus client; no physical device was contacted.
All rule files were written in temporary directories; no firewall rules
were deployed. Socket tests required execution outside the filesystem/network
sandbox after the initial bind attempts returned PermissionError.

The historical model's earlier smoke check did not establish accuracy. It
is now rejected by default. Retrained candidates use sklearn 1.9.1 and the
corrected shared scorer. Both chronological and pre-attack held-out tests
still flag 100% of normals; neither is approved for deployment. Reports are
in `validation/corrected/model-report.json` and
`validation/corrected-pre-attack/model-report.json`.
The missing-file log in unittest output is an intentional negative test.

Still pending: deployed-lab Modbus tests beyond the supported FC03/FC06 map,
actual captured-packet SEM decoding, trained-model held-out accuracy, concurrency stress,
Snort syntax validation/reload and real traffic blocking, Main SCADA
forwarding/isolation, full lab end-to-end acceptance and performance targets.
Scapy is unavailable in this environment. See `test-plan.md` for scenarios.

Full unittest output: `test-results.txt`.

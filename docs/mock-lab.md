# Ubuntu mock SCADA integration

For the current **Stage-1-only Kali demo**, use
[the walkthrough and screenshot guide](kali-stage1-demo.md). The original
fixture instructions below are historical and do not describe the current
trained Stage-1 demo.

Stop the temporary HTTP listener on port 5020 first. These files must be
present in the Ubuntu checkout; edits in another workspace are not
automatically transferred to the VM.

On Ubuntu, from the project root with the venv activated:

```sh
python run_mock_lab.py --listen-host 192.168.58.105
```

This runs the gateway on Ubuntu port 5020 and a mock SCADA on loopback port
15020. The mock is inaccessible directly from Kali. Test classifications
are deterministic: FC06 register 20 value 1 is BLOCK; other valid supported
requests are ALLOW. This is a forwarding integration fixture, not the trained
anomaly detector, and does not deploy rules to pfSense.

Copy `lab_modbus_client.py` to Kali, then run:

```sh
python3 lab_modbus_client.py --host 192.168.58.105 --case normal
python3 lab_modbus_client.py --host 192.168.58.105 --case attack
```

Expected evidence in the Ubuntu terminal:

- Normal: LAB_GATEWAY ALLOW and MOCK_SCADA register 30 value 1.
- Attack: LAB_GATEWAY BLOCK; no MOCK_SCADA register 20 value 1 receipt.
- Both clients get write acknowledgements; acknowledgements alone do not
  prove forwarding, because the isolated Twin responds to blocked traffic.

Verify isolation directly from a second Ubuntu terminal:

```sh
python lab_modbus_client.py --host 127.0.0.1 --port 15020 --case read
cat /tmp/capstone-lab.rules
```

Mock register 20 remains 0 while the Twin's pump was set to 1. The rule file
contains the generated FC06 register-20-value-1 signature. Snort deployment,
legacy-vs-inline behavior and subsequent IPS drops remain separate tests.

Stop the launcher with Ctrl+C. No extra pfSense rule is required: use the
existing Kali-to-Ubuntu TCP 5020 pass rule.

## Reproducible local confusion matrices

Run the fixture and the existing trained process model against actual loopback
TCP gateway/mock SCADA servers (no physical connection or pfSense deployment):

```sh
dt-venv/bin/python evaluate_mock_scada.py --output-dir validation/mock-scada/fixture
dt-venv/bin/python evaluate_mock_scada.py --model validation/swat-process/detector_candidate.pkl --output-dir validation/mock-scada/trained-model
```

Each output directory contains `confusion-matrix.svg`, `report.json`,
`results.jsonl`, `telemetry.jsonl`, and `runtime.log`. The script asserts that
SCADA receipt agrees with every gateway decision. It uses fresh pipelines per
episode and five repeats of eight commands per scenario. Scenario intent is
assigned before inference. These are gateway decision matrices, including any
pipeline enforcement effects, rather than isolated classifier benchmarks.
Use a fresh output directory for a new experiment to retain earlier evidence.

Measured on 27 October 2026:

| Run | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fixed fixture, 120 commands | 80 | 0 | 0 | 40 | 100% | 100% | 100% | 100% |
| Trained SWaT process pipeline, 160 commands | 40 | 40 | 80 | 0 | 25% | 0% | 0% | 0% |

Fixture scenarios are normal reads, normal valve writes, and designated pump
attacks. The trained-model run additionally includes repeated dosing commands.
Attack labels include early commands before harmful process effects become
observable, so detection delays count as false negatives. Repeated episodes
are correlated; these synthetic results do not establish real-world accuracy
or replace held-out dataset evaluation. The fixture's perfect result verifies
its predetermined branch behavior, not ML accuracy. All 280 destination receipt
checks passed. The repository regression run completed 137 tests with 12 skips
and no failures (125 executed successfully).

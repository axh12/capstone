# Research workflow: dataset, Twin, detection, SEM and pfSense

The `validation/` and `artifacts/` directories contain generated local results
and model files. They are excluded from Git; run the training and validation
commands below to create those artifacts in your own environment.

## Scope and evidence

This project has no physical SCADA/PLC. The Python mock SCADA is an isolated
Modbus register endpoint used to check whether the gateway forwards a request.
The integrated Physics Engine is the Digital Twin (DT). Its state is simulated,
not a measurement from a live plant.

The file `Anomaly Detection/aligned_sensor_network_clean.csv` contains
timestamped SWaT sensor/actuator readings, aggregate network statistics,
labels and attack types. It does **not** contain Modbus TCP payloads, register
addresses, function codes, client/server addresses or packet timestamps.
The process and network columns **are aligned by the CSV row's timestamp**.
That row-level alignment is sufficient for an offline combined-feature
experiment, but not for attributing a row to one Modbus command or for
reproducing its network aggregate from the lab's one-source request window.
Therefore a CSV row cannot be replayed as an exact Modbus packet and cannot
by itself yield a packet-specific Snort rule. A genuine packet replay requires
an aligned packet capture or an independently recorded command trace. Do not
invent packet bytes from the label or use an attack label as a detection input.

## Intended experiment

1. Train and calibrate an anomaly ensemble on **normal** observations with a
   declared feature schema. Evaluate on later, untouched normal and attack
   observations. The detector may use process state, network statistics or a
   documented combination. Training and runtime must measure each feature in
   the same units, time window and operating domain.
2. Send actual Modbus request frames from Kali through pfSense to the Ubuntu
   gateway. The DT applies each supported command and advances its simulated
   process state. The gateway records the packet, resulting state and measured
   traffic features. This state changes in the DT even if forwarding is later
   blocked. The mock SCADA changes only when the gateway forwards an ALLOW.
3. The ensemble scores the combined observation. SEM concurrently decodes
   **observed** packet details and extracts process/network context. SEM's
   candidate is not a detection verdict.
4. On ALLOW, the gateway forwards to mock SCADA. On BLOCK, it withholds the
   request, returns the Twin response, records the decision and invokes the
   emergency Twin action.
5. When an anomaly can be attributed to an observed FC06 register/value
   command, SEM generates a command-specific Snort rule. The SSH helper
   validates and installs it in pfSense's managed custom-rule section. A
   repeat of that command should generate a Snort Drop alert; an unrelated
   normal command should still reach mock SCADA. A statistical anomaly with
   no attributable packet signature is logged; it cannot safely become a
   packet-specific rule from aggregate data alone.

This tests the proposed response chain for observed scenarios. It does not
establish general zero-day detection or physical-process fidelity. A novel
actuator value is an unfamiliar state, not proof of malicious intent.

## Two currently distinct data paths

**Historical SWaT evaluation:** `validate_detector.py` can evaluate the
original sensor/network profile, which includes stage-5 measurements the
Twin cannot produce. It also offers two explicitly mapped state profiles:
`swat-stage1` uses LIT101, FIT101, FIT201, LIT301 and FIT301; `swat-process`
adds the historical AIT202 pH reading. These two profiles can run against the
integrated Twin. No label, packet command or aggregate network value is
presented to the detector as a substitute for a missing runtime feature.

Train and evaluate the shared process profile with chronological normal-only
training and separate normal calibration:

```sh
dt-venv/bin/python validate_detector.py \
  --data 'Anomaly Detection/aligned_sensor_network_clean.csv' \
  --profile swat-process --output-dir validation/swat-process
```

The artifact stores the median operating point from **training normals**.
The gateway initializes its Twin near that point before evaluating requests;
held-out observations do not set the initial state. Its simplified physics
can still drift from the historical SWaT process. Never compare a model
trained on raw SWaT network aggregates with the gateway's current per-request
network measurements as though they shared a time window.

On the present 60/20/20 chronological split, the `swat-process` held-out set
has 1,321 normal and 1,319 attack rows. The model flagged 808 attacks,
missed 511, and flagged 4 normal rows (61.3% recall; 0.30% observed normal
false-positive rate). These are **offline historical results**, not a live
VM acceptance result. One timestamped dataset can contain neighboring,
correlated samples and operating drift.

In a local gateway/Twin/mock-SCADA smoke test, two benign valve writes were
allowed. A single dosing-pump write was also allowed because one physics
step changed pH only slightly. With sustained dosing, the 33rd write crossed
the threshold, was withheld from mock SCADA, and produced a command-specific
rule for FC06 register 23 value 1. The first 32 writes were forwarded. A
following benign valve write was allowed. This is delayed detection of a
simulated process change, **not** proof that the first harmful command would
be prevented. The rule was not deployed to pfSense during that smoke test.

In a later VM run with the original gateway policy, 40 consecutive register-23
writes produced 32 ALLOW and 8 BLOCK decisions. A subsequent register-30 write
still scored above threshold because the simulated process remained anomalous;
it was blocked and incorrectly produced a register-30 rule. Its Modbus
acknowledgment was a Twin response, not a mock-SCADA receipt. This was a
**failed selectivity check**.

The revised state-only gateway policy evaluates an actuator intervention
against the *opposite actuator value* from the same pre-request Twin state,
using the same random-number state and one physics tick. It only attributes a
new command rule when the requested state crosses the trained threshold and
the opposite state does not. A previously attributed command is quarantined
within the running gateway. A blocked candidate is withheld from mock SCADA
and rolled back in the authoritative Twin before its emergency action. An
unattributed process alarm is still logged but does not by itself block an
unrelated FC06 command or generate a new command rule. In a local smoke test
with the SWaT-trained artifact, the revised policy gave 32 ALLOW and 8 BLOCK
for dosing writes, then ALLOW for register 30; only the register-23 rule was
written. pfSense verification of this revision remains pending.

The later Kali-to-Ubuntu VM repeat confirmed 32 ALLOW and 8 BLOCK dosing
writes, then ALLOW for register 30; only the register-23 rule was generated.
pfSense deployment was disabled for that run. A subsequent VM check confirmed
that blocked writes now return Modbus exception 04 instead of a success echo.
The client saw writes 33–40 rejected, the normal register-30 write acknowledged,
and a direct mock-SCADA read found register 23 OFF after the safety action.

The inline gateway now aggregates each source IP's requests in a trailing
60-second window and re-evaluates that window on every arrival before
forwarding the current request. AD and SEM execute concurrently on the shared
observation. SEM only attributes a command-specific rule to the current
request. This changes the recorded traffic statistics, but the current
`swat-process` detector consumes only process-state features, so it does not
establish earlier burst detection. A network-aware detector requires training
and calibration on the same 60-second window schema; the older native model
used per-request network measurements and is not comparable without retraining.

The mock-lab launcher now also connects the Twin's emergency action to a
**lab-only mock safety hook**. When the first dosing write is attributed and
blocked, the hook updates the mock's pump registers to OFF and records a
`MOCK_SCADA_SAFETY` event; the blocked write remains absent from the mock's
received Modbus-request list. A local SWaT-model smoke test observed 32
forwarded dosing writes, 8 blocked dosing writes, a later allowed valve write,
one mock safety event setting register 23 to 0, and an exception response for
the first blocked write. This direct in-process hook is an experimental safety
controller, **not** a verified network command or physical actuator response.

This is **model-based attribution**, not proven physical causality. The
counterfactual uses simplified Twin equations, an opposite value that may not
be a safe real-plant alternative, and one request per simulated physics tick.
The first 32 dosing writes still passed. Do not enable unattended pfSense
deployment from this profile until the Twin's command/state dynamics,
post-alarm recovery and attribution error rate are validated independently.

**VM gateway experiment:** `run_mock_lab.py --model` uses a model trained on
29 features recorded by this gateway: simulated Twin state, Modbus command
and per-request network measurements. This small native dataset was collected
from generated Kali requests, **not** from the historical SWaT CSV. Traffic
rates are currently per request, so burst/rate detection is not validated.
The latest evaluated candidate still produced 12 false alarms among 30 normal
observations. Do not enable unattended enforcement based on that candidate.

To join these paths scientifically, obtain time-aligned raw packet/command
records for the historical process, or collect representative new gateway
traces with both legitimate and abnormal sessions. Define an explicit sensor
and actuator mapping, align time windows and units, and train/evaluate on the
same schema the gateway emits. If only CSV aggregates are available, report
an **offline dataset detection experiment** separately from the **packet and
rule deployment experiment**; do not present them as one replay of the same
packets.

The `swat-process` profile provides a shared **state-only** training/runtime
schema. To add network traffic to that model, collect matching network
windows at the gateway or obtain historical packet captures with a known
window definition and packet-size units. Anomalies that arise only from a
sensor trend need causal attribution before an observed command becomes a
Snort drop rule; the current SEM exports the matching current FC06 command
when the detector flags its resulting state.

The offline `swat-aligned` profile explicitly keeps six mapped process
readings and twelve network aggregates from **the same timestamped CSV row**.
It can test the combined-feature research hypothesis without inventing
packet bytes. It is rejected by the live gateway because its network scope
and measurement scale differ. Reproduce the chronological experiment with:

```sh
dt-venv/bin/python validate_detector.py \
  --data 'Anomaly Detection/aligned_sensor_network_clean.csv' \
  --profile swat-aligned --output-dir validation/swat-aligned
```

An initial reproduction on 14 October 2026 flagged 805 of 1,319 held-out
attacks but also 917 of 1,321 held-out normal rows (61.0% recall, 69.4%
false-positive rate). This does not support automatic blocking. The CSV's
twelve selected network columns had only 64 distinct vectors across 13,196
rows and were unchanged between consecutive rows about 99.5% of the time;
the cause and effect of this repeated aggregation require separate data
provenance analysis before network claims.

## Paired gateway-window experiment

The `gateway-window` profile is a separate, runtime-compatible experiment.
It uses six simulated process readings and twelve measurements of the same
source IP's trailing 60 seconds of complete Modbus request frames. It does
not claim that these request counts are the SWaT CSV's plant-wide network
counts. Conversion rejects unlabeled events, old per-request observations,
window/rate mismatches and mixed-source windows. A manifest assigns whole
sessions to train, calibration and test; training and calibration sessions
must be normal, and held-out test sessions must contain both normal and
attack examples. The model artifact stores its feature order, window duration
and measurement scope; a gateway with another window length refuses it.

Collect **new** labeled sessions with `run_mock_lab.py --telemetry-file ...
--label normal` (or `--label attack` for an independently specified attack
scenario). Include varied harmless rates and actuator sequences. Use one
JSONL file per session and keep the gateway's default 60-second window.
The label describes the scenario, not the detector's decision. Example
manifest, with paths relative to the manifest file:

```json
{"sessions": [
  {"id": "normal-train-1", "path": "normal-train-1.jsonl", "split": "train"},
  {"id": "normal-cal-1", "path": "normal-cal-1.jsonl", "split": "calibration"},
  {"id": "normal-test-1", "path": "normal-test-1.jsonl", "split": "test"},
  {"id": "attack-test-1", "path": "attack-test-1.jsonl", "split": "test"}
]}
```

```sh
dt-venv/bin/python telemetry_to_dataset.py \
  --window-manifest validation/gateway-sessions.json \
  --output validation/gateway-window.csv
dt-venv/bin/python validate_detector.py \
  --data validation/gateway-window.csv --profile gateway-window \
  --protocol declared_sessions --output-dir validation/gateway-window
```

At least 31 normal training observations and 10 normal calibration
observations are required. More varied sessions are needed for credible
accuracy and detection-delay estimates. Do not enable automatic pfSense
deployment solely because the converter and model run. A network-only
anomaly is logged but does not become a command-specific drop rule from
one packet: the current attribution guard requires the candidate command's
predicted process effect to cross the threshold while its alternative does
not. This prevents a traffic-rate alarm from making an overbroad Modbus
payload rule. The historical SWaT top-20 model remains an offline experiment
because its seven other sensors are unavailable from this Twin.

## Isolate the ensemble in the VM

For a diagnostic run with the native model, use `--ensemble-only` to disable
the normal-learned actuator-value override. Start without automatic pfSense
deployment while measuring false alarms:

```sh
dt-venv/bin/python run_mock_lab.py --listen-host 192.168.58.105 \
  --model validation/native-tail/detector_candidate.pkl --ensemble-only \
  --telemetry-file validation/ensemble-only-run.jsonl
```

Telemetry records `ensemble_score`, `ensemble_only_score`, `threshold`,
`detection_basis`, the allow/block decision and enforcement outcome. Supply
`--deployment-config pfsense-deployment.json` only after independent accuracy
review. Capstone-managed pfSense rules persist across gateway restarts and
new deployments add distinct command rules without deleting earlier ones.
Inspect the managed section before each experiment: a command with an existing
rule will be stopped by Snort before it can test the detector again. Use a new
command signature for an accumulation test; clear rules only when an isolated
baseline is explicitly required. Compare the first request's gateway decision,
SEM signature and deployment result with the repeated request's pfSense alert
and the mock SCADA receipt log.

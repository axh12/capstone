# Inline Modbus gateway

The default research runner uses mock SCADA. An optional physical-forwarding
mode is implemented for the updated Nano sketch, but has not yet been verified
on the rig. Its confirmed layout is **box 1 (stored water) → automatic
pump 1 → box 2 (ultrasonic level sensor) → manually switched pump 2 and flow
sensor → box 3**. Pump 1 turns on below a lower box-2 level and stops at the
full threshold; pump 2 runs from a separate switch. The LCD displays box-2
water level and the box-2 → box-3 flow rate.

The optional `three_tank_transfer` Twin maps box 1 to LIT201, box 2 to
LIT101, and box 3 to LIT301. Its SWaT-style actuator names `mv101` and `p101`
represent pump 1 and pump 2 respectively. The **measured** outlet flow is
FIT201; FIT101 is an **estimate** of the unmetered box-1 → box-2 flow. The
default `swat` mode remains separate for historical SWaT experiments; its
Stage 2 chemistry and Stage 3 equations do not describe this rig. The box-2
one-tick tank balance is
`delta_LIT101_mm = (FIT101 - FIT201) * dt_seconds * 1000 / (3600 * tank_area_m2)`
with flows in m3/h. Nominal inlet and pump flows are 4.37 and 2.33 m3/h,
estimated from normal rows in the local aligned SWaT trace; the 2.0 m² tank
area and remaining noise/boundary behavior are provisional simulation
parameters. Without a sensor, `three_tank_transfer` uses provisional 500/800
mm fill thresholds. With the supplied Nano text sketch, the Twin uses the
**raw ultrasonic distance** instead: pump 1 turns on at ≥8 cm and off at
≤2 cm, just as the sketch does. An empty-box distance is not required or
inferred from a jittering reading above 8 cm. Tank areas and flow rates are
provisional and matter if evaluating quantitative prediction accuracy. If a
stable empty-distance reference is measured later, the optional conversion uses the Nano's
actual settings and measurements before claiming a calibrated match.
For a top-mounted distance sensor, the eventual conversion is
`water_level_mm = empty_tank_distance_mm - measured_distance_mm`, subject to
the sensor mounting offset and usable tank height. Both distances must use
the same units. The serial bridge performs this conversion once the Nano is
connected.
To exercise the three-box topology with local fixture classifications and mock
SCADA, run `dt-venv/bin/python run_mock_lab.py --plant-topology three_tank_transfer`
on Ubuntu; it binds localhost by default. This mode uses provisional SWaT
flow rates and tank areas and is **not a calibrated rig model**. The runner
rejects existing SWaT model artifacts in this mode because they were trained
on different dynamics; a future rig-specific artifact must declare its
topology. No command reaches the unconnected rig.

For a Nano connected by USB, the optional read-only serial bridge expects one
UTF-8 JSON object per line at 115200 baud. The Nano should print the same
numeric values it calculates for the LCD, for example:

```json
{"water_level_mm":275.0,"outlet_flow_lpm":10.0,"inlet_pump_on":1,"outlet_pump_on":0}
```

`water_level_mm` is the measured water depth in box 2. If a JSON sketch only
reports sensor distance, send `distance_mm` instead and configure
`--empty-distance-mm`. Send exactly one of these fields. The original text
sketch can use raw distance without an empty-distance reference. Flow can be
`outlet_flow_lpm` (litres/minute) or `outlet_flow_m3h` (m³/hour); send exactly
one. The two
binary pump-state fields are optional but should be emitted if the Nano knows
the relay states. The bridge converts water depth to `LIT101` in mm and flow
to `FIT201` in m³/h; no serial writes or physical pump commands are sent.
Use the stable device path in `/dev/serial/by-id/` when available. If the Nano
already sends water level, the Ubuntu command is:

```sh
dt-venv/bin/python run_mock_lab.py --plant-topology three_tank_transfer \
  --stage1-serial /dev/serial/by-id/YOUR_NANO --stage1-baud 115200
```

Add `--empty-distance-mm EMPTY_MM` only for `distance_mm` telemetry.

### Original Arduino Nano sketch

The supplied sketch does **not** print JSON. It prints a pair of lines once
per second at **9600 baud**:

```text
Distance: 8 cm
Flow: 7.50 L/min
```

Its ultrasonic trigger and echo are Nano pins 5 and 6. Pin 7 drives pump 1's
active-low relay: distance ≥ 8 cm turns pump 1 on, and distance ≤ 2 cm turns
it off; readings between those points retain the previous relay state. The
original pasted sketch returned 99 cm on no echo, which could turn pump 1 on.
The repository copy at `arduino_stage1/arduino_stage1.ino` returns -1 cm and
turns pump 1 off on no echo; the bridge rejects either invalid reading.
The flow sensor is on interrupt pin 2 and the sketch reports pulses / 7.5 as
L/min. Pump 2 is operated by a manual switch; the sketch reports neither that
switch's position nor either relay state. The LCD's `Level:` label displays
**sensor-to-water distance**, not water depth. A missed echo still prints
`Distance: -1 cm` on serial and turns pump 1 off. The LCD instead holds the
last valid distance for up to three seconds and adds `*` to mark it as held;
a longer outage displays `NO ECHO`, so an old value is not shown indefinitely.
The sketch keeps the original `lcd.clear()` and cursor layout.
The repository sketch also spaces ultrasonic readings by 70 ms and accepts
`P1 <sequence> <0|1>` on the same 9600-baud serial connection. It responds
`ACK P1 <sequence> <value>` after setting pump 1's relay, or
`ERR P1 <sequence> SENSOR_OR_FULL` when ON is unsafe. The override lasts at
most 30 seconds before automatic 8/2 cm control resumes. No echo or a full
box turns pump 1 off even during an override. Pump 2 remains manual. These
firmware changes require uploading the repository sketch; the flow calculation
and LCD layout are unchanged.

Use the current sketch without reflashing by setting its format and baud:

```sh
dt-venv/bin/python run_mock_lab.py --plant-topology three_tank_transfer \
  --stage1-serial /dev/serial/by-id/YOUR_NANO \
  --stage1-serial-format arduino-text --stage1-baud 9600
```

Before starting the gateway, verify that the USB passthrough and serial
telemetry work. Close Arduino IDE's Serial Monitor so it does not hold the
port, then run this on the Ubuntu VM (replace the device path with the entry
shown by `ls -l /dev/serial/by-id/` or use `/dev/ttyUSB0`):

```sh
dt-venv/bin/python run_mock_lab.py --plant-topology three_tank_transfer \
  --stage1-serial /dev/serial/by-id/YOUR_NANO \
  --stage1-serial-format arduino-text --stage1-baud 9600 \
  --stage1-probe
```

The probe prints five `measured` records, the corresponding `twin_state`
snapshots, and a one-step `simulated_next_state` for each sample. It then
exits without opening the gateway or applying Snort rules.
If the sensor briefly returns no echo, the probe marks that sample invalid
and continues; it never inserts the invalid reading into the Twin.
`distance_cm` and `FIT201` come from the physical rig; other Twin fields
remain simulated unless separately measured and calibrated. Once the probe
works, omit `--stage1-probe` to refresh the Twin continuously and before each
gateway decision. A `Distance: -1 cm` no-echo reading is rejected rather than
used as a water level.
The attached FTDI device has also been observed printing just `-1 cm` without
the `Distance:` prefix. The bridge accepts either prefix format, but `-1 cm`
still means the ultrasonic sensor reported no echo. Occasional no-echo samples
and blank separator lines are skipped; if no valid distance arrives before the serial read times out,
the probe reports an invalid sample and the gateway does not forward a command. Check the
sensor/wiring and get a valid nonnegative reading before relying on the live
Twin state.
The live port has also emitted `stance: -1 cm`, with the initial `Di` missing.
The parser accepts this exact prefix loss to recover the numeric reading;
repeated prefix loss should still be investigated on the Nano serial link.

Without an empty-distance reference, the bridge sends `distance_cm` and
`FIT201` to the Twin and does **not** manufacture a measured `LIT101` depth.
The Twin can still mirror pump 1's hysteresis from raw distance and simulate
the direction of a candidate command's effect. The amount of predicted
distance change still depends on provisional tank areas and pump flows. If a
stable reference is measured later, optionally pass `--empty-distance-mm`;
the bridge then also computes `water_depth_mm = empty_distance_mm - 10 *
displayed_distance_cm`. The 8/2 cm switch points are not tank depths.
The 7.5 flow-pulse factor and all Twin tank areas/pump rates still require
calibration on the physical hardware. By default the serial bridge only reads
telemetry and mock SCADA remains the downstream destination. The explicit
`--physical-forward` mode instead sends allowed FC06 register-30 pump-1 writes
to the Nano and waits for its matching acknowledgement. It rejects register
20 (manual pump 2) and all other physical writes. The mode requires a model
calibrated for `three_tank_transfer` plus `--ensemble-only`; the existing SWaT
model does not qualify. It does not start mock SCADA.

After uploading the updated sketch and training a rig-specific model, the
physical-forwarding runner is:

```sh
dt-venv/bin/python run_mock_lab.py --listen-host 192.168.58.105 \
  --plant-topology three_tank_transfer \
  --stage1-serial /dev/serial/by-id/usb-FTDI_FT232R_USB_UART_A5069RR4-if00-port0 \
  --stage1-serial-format arduino-text --stage1-baud 9600 \
  --model validation/rig/detector_candidate.pkl --ensemble-only \
  --physical-forward --telemetry-file validation/physical-run.jsonl
```

Use `--deployment-config pfsense-deployment.json` only when the model and
serial command path have passed local checks. The command above does not
enable pfSense deployment. Do not run it with the old measurement-only sketch:
that sketch cannot acknowledge a command, so the gateway will return a
Modbus device error. The Nano's acknowledgement proves receipt and initial
relay command, not sustained pump motion or water flow; verify those from the
physical rig. Normal command expiry and no-echo safety can turn the relay off
after an acknowledgement.

The bridge refreshes the Twin continuously and again before scoring each
gateway request. An invalid or missing serial reading causes the request to
fail rather than forward without physical context. A live read-only probe on
2026-10-23 read five valid Nano samples through the FTDI serial device:
distances 6, 2, 3, 2, and 3 cm appeared in the Twin's `distance_cm` field;
`FIT201` was 0.0 throughout because no nonzero outlet flow was observed.
This verifies the sensor-to-Twin path for those samples, not the trained
detector or physical command forwarding. A subsequent continuous gateway run
on the same FTDI link received repeated truncated fragments such as `cm` and
`L/min`; the serial connector rejected them, so continuous synchronization
was not verified. A repeat probe returned 0/5 valid samples, all with the
`L/min` fragment. After reconnecting USB, a later probe read 5/5 valid
samples at 3 cm. A 30-second read returned 15 valid reads, 5 no-echo errors,
and 2 timeouts. The LCD `*` holds a prior valid value while raw serial may
still report `-1`; continuous reliability remains to be verified after the
updated sketch is uploaded. Pump 2 is operated by a separate
manual switch, not a Nano relay. Its flow sensor measures box-2-to-box-3 flow,
but the Nano does not report the switch position; zero flow alone cannot
distinguish a switched-off pump from a running pump with no water. Before
`--model --ensemble-only` can be used for this rig, collect normal and labeled attack data from this rig, train and
calibrate an ensemble for its available sensors, and declare
`plant_topology=three_tank_transfer` in the artifact. A SWaT-trained ensemble
is incompatible with this rig's measured sensor schema.

A later live gateway check on 2026-10-23 exposed partial serial fragments
(`0 L/min`) that made reads fail. The text parser now discards incomplete
fragments and waits for a fresh complete pair; it still rejects no-echo
readings. A repeat probe then read 5/5 valid pairs at 2 cm with zero outlet
flow. One local Modbus read reached the gateway, recorded `distance_cm=2.0`,
and was served by mock SCADA. Subsequent writes were withheld when the Nano
returned only no-echo samples. The live test used fixed fixture decisions,
not a trained rig anomaly model, and sent no command to the physical Nano or
pfSense. The runner uses a 1.5-second serial read budget and one-second
background polling so sensor failures return a Modbus error before the lab
client's five-second timeout; this is still not a substitute for reliable
sensor data.

The intended data paths have separate roles: **Nano → Twin supplies measured
telemetry**; **gateway → Twin applies a candidate command to the simulation**;
**gateway → Nano forwards only an allowed pump-1 command in physical mode**.
Regressions verify that blocked commands never reach the downstream adapter
and that a downstream rejection rolls back the candidate Twin state. In the
default mock lab, allowed requests still go to local mock SCADA.
The gateway currently advances the physics by one fixed tick per command,
not by wall-clock elapsed time, so this is not yet a continuous-time replica
of an operating rig. The Stage 1 wiring follows the
[SWaT subprocess description](https://github.com/scy-phy/minicps/blob/master/docs/swat-tutorial.rst)
and the [SWaT tank/flow diagram](https://eskang.github.io/assets/papers/water-sescps16.pdf).
In the historical CSV, status 2 means open/on and status 1 means closed/off;
the gateway translates this conceptually to binary 1/0 commands.

The existing calibrated detector artifacts were generated with the earlier
reversed Stage 1 dynamics. Re-evaluate/retrain and recalibrate them against
new normal and attack sessions before using this revised Twin for deployment
or interpreting an allow/block result as validated detection accuracy.

The historical dataset does not provide raw Modbus requests; see
[Research dataset workflow](research-dataset-workflow.md). The gateway accepts
the explicitly mapped `swat-stage1` and `swat-process` state profiles, the
`native-twin` profile, and a newly trained `gateway-window` profile. The
latter requires separately collected, human-labeled 60-second gateway
sessions; it is not the historical SWaT top-20 model. Add
`--ensemble-only` to disable the separate learned actuator-value check when
measuring what the anomaly ensemble itself detects.

`modbus_gateway.py` is the inline entry point. The old `Digital Twin/Twin.py`
server and passive packet sniffer are not forwarding gateways. Do not bind
the old server and gateway to the same port.

Start with an explicit Main SCADA destination and trained model:

```sh
dt-venv/bin/python modbus_gateway.py \
  --listen-host 127.0.0.1 --listen-port 5020 \
  --scada-host SCADA_HOST --scada-port 502 \
  --model validation/native/detector_candidate.pkl \
  --rules-file /tmp/capstone-custom.rules
```

Replace SCADA_HOST with the Main SCADA endpoint, never the read-only physical
Stage 1 reference. In the lab, set the listening interface explicitly and
route clients through this gateway. The command above was not used to
contact a real SCADA device during testing.

The gateway keeps a trailing 60-second request batch separately for each
source IP. Each complete request joins its source's current window, is
simulated in the isolated Physics Engine, recorded as telemetry, and analyzed
before forwarding. AD and SEM run concurrently over the same observation:
AD receives the window's network statistics and current Twin state, while SEM
receives the window statistics and summarizes its observed Modbus writes.
Only the current command can produce a command-specific rule. The window is scored on **every arrival**; the gateway
does not wait a full minute or queue commands for a later flush. The current
window count, duration, and command counts appear in telemetry's `detection` field. Change the
duration with `--window-seconds` on either gateway launcher.

The current `swat-process` artifact uses process-state features only. Its
ensemble does not consume packet count or traffic rate, even though the
60-second statistics are recorded and available to SEM. A model trained on
per-request or 5-second network features cannot be evaluated as a 60-second
network model without retraining and recalibration on matching windows.
The `gateway-window` artifact must declare a 60-second per-source request
window. The gateway refuses another duration or feature order. A network-only
alarm does not automatically generate a content-only Snort drop rule for a
single FC06 command; that would also block harmless uses of the command.

A supported request classified
ALLOW is forwarded once; its upstream reply is returned. A blocked FC06 write
returns Modbus exception 04 rather than a success echo; a blocked FC03 read
can return the Twin's simulated value. The telemetry distinguishes a policy
block from an internal device failure because Modbus has no dedicated
"blocked by anomaly detector" exception code. Neither blocked request
contacts SCADA. Invalid requests are never
forwarded. Detector/SEM/internal errors return exception code 04. An
upstream failure is not retried, since a write may already have arrived.

For the mapped SWaT state-only profiles, an FC06 write is also compared with
the opposite actuator value from the same pre-request Twin state. A new
command rule requires a detector threshold crossing in the requested state
while the opposite state remains below threshold. An already quarantined
command stays blocked. A process alarm without that attribution is logged but
does not by itself block another FC06 write. Blocked candidates are rolled
back in the authoritative Twin before the emergency action. This comparison
depends on the simplified Twin and is experimental; see the research workflow
before enabling pfSense deployment.

`run_mock_lab.py` additionally passes a lab-only safety hook to the mock
SCADA. After the Twin emergency response, the hook turns the mock's pump
registers OFF and prints `MOCK_SCADA_SAFETY`. The generic gateway has no such
hook by default; this mock update is not evidence of a physical safety
command being delivered to a real PLC.

This initial protocol implementation supports FC03 and FC06. Its explicit
holding-register map is:

| Registers | Values |
| --- | --- |
| 1, 2, 3 | LIT101, LIT201, LIT301 in integer mm |
| 10, 11, 12 | FIT101, FIT201, FIT301, truncated to integer units |
| 20, 21, 22, 23 | p101, p201, p301, p203 (binary writes) |
| 30, 31 | mv101, mv201 (binary writes) |

In `three_tank_transfer`, register 30 represents pump 1, moving box 1 → box
2, despite its SWaT-style name `mv101`. Pump 1 normally follows the box-2
low/full thresholds; a candidate register-30 write simulates an override.
Register 20 represents pump 2, moving box 2 → box 3, despite its `p101`
name. On the physical rig it runs only while the manual switch is pressed;
the Twin does not turn it on automatically. These register meanings are
simulation conventions, **not a verified Nano command map**. Registers 1,
2, and 3 report the simulated levels of boxes 2, 1, and 3 respectively.
Register 10 reports estimated box-1 → box-2 flow; register 11 reports the
box-2 → box-3 flow, which can be refreshed from the Nano's sole flow meter.

This map follows the current Physics Engine and differs from the legacy
Twin's P102/MV301 assignments. Align the client and Main SCADA maps before
lab use. Other functions and unmapped registers return Modbus exceptions.
Requests are serialized across clients to preserve state/feature ordering;
the simulation advances once per accepted write, not on a background clock.

Generated Snort rules are written to the configured file. The generic gateway
does not deploy or reload pfSense unless deployment is explicitly configured.
The pfSense SSH helper merges each new generated rule into the saved
Capstone-managed section, deduplicating by SID. Existing managed rules survive
gateway restarts and later deployments; an empty rule file is a no-op. To
intentionally remove only those rules, run the deployment script with
--config pfsense-deployment.json --clear-managed. Do not run that command
between accumulation tests. A rule already installed in inline Snort can stop
its matching request before the gateway sees it, so use a new FC06
register/value signature when testing detector discovery again. The current
gateway only supports the mapped registers above, not arbitrary register
ranges.

Models must use calibrated scoring, match the installed sklearn version,
and have a supported feature profile. The historical full-SWaT artifact is
preserved but rejected by the gateway because its Stage 5 sensors are absent.
Local socket tests do not establish model
accuracy. See `remaining-integration.md` for the unresolved data requirement,
native observation recording and automatic deployment configuration.

Run the full suite with `dt-venv/bin/python -m unittest discover -s tests -v`.
Socket tests require permission to bind loopback sockets. No real firewall
reloads or physical Stage 1 writes are performed by the tests.

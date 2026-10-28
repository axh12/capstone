# Kali → Ubuntu Stage-1 demonstration and screenshot checkpoints

Kali is your attacker/user VM. Ubuntu runs the inline gateway and mock SCADA.
Copy the updated demo kit to Ubuntu, extract it, and run from its project root.
Only `stage1_demo.py` must be copied to Kali; it uses Python's standard library.
The project cannot operate your Kali terminal from this chat.

Use the Ubuntu address reachable from Kali. The earlier project address was
`192.168.58.105`; substitute your current address if it changed. The Ubuntu
gateway must listen on that address, not only 127.0.0.1. Mock SCADA stays on
127.0.0.1:15020. Use the lab's existing Kali-to-Ubuntu TCP 5020 path.

## Prepare Ubuntu

Use the project environment with numpy, pandas, scikit-learn and scapy. Stop
the old lab launcher with Ctrl+C before starting a fresh demo; its quarantine
and depleted tank state must not carry over. Do not delete previous evidence.

The kit includes the tested model/profile. If your scikit-learn version differs
from the supplied model, train both artifacts locally with the bundled CSV:

```sh
python3 -m venv dt-venv
dt-venv/bin/python -m pip install numpy pandas scikit-learn scapy
dt-venv/bin/python validate_detector.py --profile swat-stage1-only \
  --output-dir validation/swat-stage1/model
dt-venv/bin/python swat_mock_profile.py
```

The kit's `demo-runtime-versions.json` records the locally tested versions.
Retraining on another library version can change the demo. Rehearse first:

```sh
dt-venv/bin/python verify_stage1_demo.py
cat validation/stage1-demo-proof/proof.json
```

This rehearsal uses real loopback TCP and the actual model; it does **not**
produce evidence that Kali or pfSense was exercised.

## Open the live demo

Ubuntu terminal 1:

```sh
dt-venv/bin/python run_stage1_demo_server.py --listen-host 192.168.58.105
```

The launcher prints a fresh session directory and the exact watcher command.
Open Ubuntu terminal 2 in the same project directory and run that command,
which has this form (replace SESSION with the printed session name):

```sh
python3 watch_stage1_demo.py \
  --telemetry validation/stage1-demo-sessions/SESSION/telemetry.jsonl --from-start
```

On **Kali**, from the directory containing `stage1_demo.py`:

```sh
python3 stage1_demo.py --host 192.168.58.105 --case walkthrough
```

The walkthrough pauses **before each next stage** and tells you when to take
the screenshot. Press Enter only after saving it. Arrange the Kali and Ubuntu
VM windows beside one another so transaction IDs can be compared.

| Screenshot | Take it when the walkthrough says… | Evidence to include |
| --- | --- | --- |
| 1 — Setup | Before sending the normal command | Ubuntu `MODEL MODE: swat-stage1-only`, scope, listening address, no pfSense deployment, and Kali destination |
| 2 — Normal allowed | After tx=1000 | Kali `ALLOWED`; Ubuntu `tx=1000 / ALLOW / forwarded=YES`; benign P101 OFF command |
| 3 — Attack blocked | At the first rejection | Kali rejected transaction ID; Ubuntu same ID with `BLOCK / forwarded=NO`, score, threshold and counterfactual reason |
| 4 — Repeat and rule | After the saved rejected packet is replayed | Same transaction ID and bytes; Ubuntu quarantine reason, command-specific Snort rule, mock pumps OFF |
| 5 — Recovery allowed | After tx=1000 is allowed again | Identical benign P101 OFF packet acknowledged; Ubuntu `ALLOW / forwarded=YES` after the attack block |

For mock-register proof, open a third **Ubuntu** terminal while Kali is paused:

```sh
python3 stage1_demo.py --host 127.0.0.1 --port 15020 --case state
```

At screenshot 2, P101 should be 0. At screenshots 3–4, P101 and P102 should
be 0 following the lab-only safety hook. Inspect the actual rule from the
session directory printed by the launcher:

```sh
cat validation/stage1-demo-sessions/SESSION/snort.rules
```

It should match FC06 register 20 value 1 (`06 00 14 00 01`). This proves rule
generation, **not** pfSense installation or IPS dropping.

## What the demonstrated block means

The benign example turns P101 OFF once. The stress example repeatedly forces
that pump ON while MV101 remains closed. The simulated tank drains by one
physics tick per write. The client stops at the first rejection and saves that
packet's fields beside the script. The repeat reuses the exact transaction ID,
function, register and value. The final benign packet is identical to the
first packet. See `validation/stage1-four-step-proof/proof.json` for the local
rehearsal's observed request count; the normal command no longer advances a
draining tick, so the count differs from the earlier pump-ON demonstration.

This is delayed detection of an unusual simulated process state. The packets
share a command; the process context changes. Do not present this as blocking
the first attack packet, a general attack classifier, or physical dry-running
protection. LIT101 was about 617 mm at the block, not an established damage
threshold. The earlier Stage-1 confusion-matrix failures remain valid; this
longer demonstration is not a replacement accuracy result.

An exception 04 alone may also mean a server failure. Claim BLOCKED only when
the matching Ubuntu transaction says `decision=BLOCK` and `forwarded=NO`.
Timeouts, connection failures and mismatched replies are errors, not successful
attack blocking. The client stops on the first rejection or at its request cap;
it does not force a success result. Record a failed rehearsal honestly.

To repeat the whole demonstration, stop the Ubuntu launcher and start a fresh
session. The live gateway quarantines the observed command within a session.

# Detector and automatic enforcement work

> This document records earlier full-SWaT and native-Twin experiments. A
> newer mapped `swat-process` state-only profile is documented in
> [Research dataset workflow](research-dataset-workflow.md). It can score
> integrated Twin state but does not yet use the dataset's aggregate network
> columns at runtime.

## Implemented locally

- Scoring is shared between training, evaluation and runtime. Both IF and LOF
  decision scores are negated because lower scores indicate outliers. Each
  component is ranked against a stored calibration-normal distribution,
  then combined with weights 0.25/0.25/0.50. Batch min/max normalization is
  eliminated. See [IF documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
  and [LOF documentation](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html).
- Artifacts record scoring version, feature schema, library version and split.
  Legacy artifacts are rejected by default; the old file is preserved.
- No invented SWaT sensor readings or source-IP-based simulated anomalies.
  Native Twin state, commands and per-request network features are recorded.
- The model launcher accepts a trained native-twin artifact. It rejects the
  incompatible SWaT profile before binding a listening socket.
- SSH automation invokes a package-aware PHP helper, not a blind overwrite
  of generated files. It merges a managed rule section into saved custom
  rules, preserves unrelated rules, backs up prior custom rules, rebuilds,
  runs Snort's configuration test, persists and requests reload. Errors
  trigger rollback; failures are recorded while gateway BLOCK stays BLOCK.
  See the [pfSense package rule handling](https://github.com/pfsense/FreeBSD-ports/blob/devel/security/pfSense-pkg-snort/files/usr/local/www/snort/snort_rules.php).
- Legacy deployment uses alert rules; inline deployment uses drop rules.
  Automation checks the configured mode and never changes interface mode.

## Detector results and unresolved data requirement

Reproduce with:

```sh
python validate_detector.py
python validate_detector.py --protocol pre_attack --output-dir validation/corrected-pre-attack
```

The default chronological protocol trains on normal samples in the first
60% of timestamps, calibrates on normal samples in the next 20%, and tests
all samples in the last 20%. The 1% calibration target is a configurable
experiment, not an agreed deployment acceptance requirement.

| Protocol | Test normals | Test attacks | False positives | True positives | Recall |
| --- | --- | --- | --- | --- | --- |
| Pre-attack baseline | 5,521 | 6,180 | 5,521 | 6,085 | 98.46% |
| Chronological 60/20/20 | 1,321 | 1,319 | 1,321 | 1,237 | 93.78% |

Both flag **100% of held-out normal samples**. Correcting software scoring
does not make this dataset a validated live detector. The pre-attack baseline
has zero network traffic; later normals have nonzero traffic and different
operating states. The live Physics Engine also lacks the dataset's seven
SWaT sensor channels. No candidate has been promoted, and no successful
accuracy claim is made.

Collect representative, human-labeled gateway observations across legitimate
commands, sensor ranges, rates and operating states. Include multiple normal
and attack sessions in chronological order so all three partitions have
appropriate normal coverage, with attacks in the test partition. A few
repetitions of one fixture command are not adequate training data.

In the mock lab, record one known-normal session:

```sh
python run_mock_lab.py --listen-host 192.168.58.105 \
  --telemetry-file validation/native-observations.jsonl --label normal
```

Stop/restart with `--label attack` for a known attack scenario. Labels are
provided by the operator; model/fixture decisions are never ground truth.
Keep this launcher attached to the mock SCADA while gathering data. Changing
the session label does not change the fixed fixture's decisions.

Convert and evaluate:

```sh
python telemetry_to_dataset.py validation/native-observations.jsonl --output validation/native.csv
python validate_detector.py --data validation/native.csv --profile native-twin --output-dir validation/native
```

After reviewing held-out metrics, use the actual model with the mock SCADA:

```sh
python run_mock_lab.py --listen-host 192.168.58.105 \
  --model validation/native/detector_candidate.pkl --telemetry-file validation/model-run.jsonl
```

This selects actual inference; it no longer forces register 20 value 1 to
BLOCK. Whether that command is malicious depends on its process context
and representative training data, not its fixture name.

## pfSense assistance needed

1. Confirm the running WAN process with `ps axww | grep '[s]nort'` in
   Diagnostics → Command Prompt. A local clone cannot access the user's VM.
2. Establish Ubuntu-to-pfSense key-based SSH, verify the host fingerprint,
   and authorize the public key for the administrative account. Never
   transfer the private key or share passwords in chat.
3. Copy `pfsense-deployment.example.json` to a local configuration and set
   the actual account/key paths. Use `mode: legacy` for the current setup.
4. Run an inspection before any deployment:

```sh
python deploy_snort_rules_ssh.py --config pfsense-deployment.json --inspect
```

Inspection uploads a temporary helper, reads interface information, and
removes the helper. It does not alter saved Snort rules. Live pfSense API
compatibility and validation/reload still require this VM check.

After successful inspection, test automation with the fixed fixture first:

```sh
python run_mock_lab.py --listen-host 192.168.58.105 \
  --deployment-config pfsense-deployment.json --telemetry-file validation/deployment-run.jsonl
```

Remove only Kali's test entry from Snort's Blocked page and remove the
manually preinstalled test SID 1781355 before the automation test. Leave
other rules intact. Trigger the test attack, check the helper result,
verify the new rule is visible after a GUI refresh, check the Snort alert,
then confirm a subsequent connection times out without a new gateway event.
Keeping the old manually loaded rule would not prove automatic deployment.

The helper syntax and rollback/merge semantics are exercised locally with
stubbed pfSense APIs. This is not evidence of successful deployment on the
actual firewall. A reload request/running PID alone does not prove the
new rule is active; a matching live alert is required.

## Inline acceptance remains a lab task

Record current interface settings and retain VM console access. Check NIC
and netmap compatibility before selecting Inline Mode in the GUI. Once
Snort starts successfully in inline mode, set the deployment JSON to
`mode: inline` and inspect again. Clear the test host block left by Legacy
Mode so it cannot mask the test.

Trigger deployment, repeat the malicious command, and prove it is dropped
before Ubuntu. Then send an unrelated normal command from the same Kali IP
and prove it reaches mock SCADA. Save packet captures and Snort logs.

Do not claim command-specific inline enforcement from the earlier host-block
test. Runtime cleanup currently redeploys rule expiration only during new
anomaly exports; idle-time expiry and concurrent GUI edits during deployment
require further lifecycle work. Avoid editing the same custom-rule instance
in the GUI while the deployment helper is applying a change.

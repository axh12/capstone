# Automated Snort response

The orchestrator can now translate the **network portion** of an anomaly
signature into stable Snort custom rules. Modbus FC06 signatures match the
function/register/value bytes and do not block a source IP. Statistical sensor features remain
in the Python/SEM pipeline because they are not observable in one packet.

## Safe export (recommended first)

```python
from orchestrator import IntegrationOrchestrator

orchestrator = IntegrationOrchestrator(
    detector_model_path="anomaly_detection_ensemble.pkl",
    use_real_network=True,
    snort_rules_path="snort_custom.rules",
    snort_blocking=False,  # writes alert rules for review
)
```

On an anomaly, concrete Modbus command signatures are written atomically to
`snort_custom.rules`. A signature without a complete command or network tuple
is deliberately skipped.

## Enforcing mode

After reviewing the generated file, set `snort_blocking=True` to generate
`drop` rules. Deployment is intentionally an explicit hook because pfSense
package paths and reload commands vary by version. For example, a controlled
wrapper can be supplied with:

```python
snort_apply_command="/usr/local/sbin/capstone-snort-reload {rules_file}"
```

The wrapper should copy the file into the pfSense Snort custom-rules location,
validate it, reload the WAN Snort instance, and return a non-zero exit status
on failure. Do not point this at an unreviewed shell command or enable blocking
on a production network without testing.

# Ubuntu mock SCADA integration

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

# Physical Arduino bridge

`physical_pump_controller/physical_pump_controller.ino` adds a line protocol
for the FTDI/USB serial connection at 9600 baud:

```text
STATUS
REMOTE ENABLE
PUMP ON
PUMP OFF
REMOTE DISABLE
```

Remote control is disabled at boot and `PUMP ON` is rejected until
`REMOTE ENABLE` is received. A missing level reading forces the relay off.
Upload only after confirming the relay type, pump voltage, isolation, and an
accessible emergency stop. The Python connector remains read-only by default.

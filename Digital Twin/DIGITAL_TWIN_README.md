# Digital Twin: Real-Time Zero-Day Attack Simulation

## Overview

The updated digital twin now implements a **realistic SCADA attack surface**. When an attacker sends a Modbus packet to modify a register, the digital twin:

1. **Receives** the malicious packet
2. **Applies** the command to global state
3. **Physics engine reacts** in real-time
4. **Sensors update** to reflect physical changes
5. **Honeypot logs** the full attack chain with consequences

---

## Architecture: Attack Flow

```
Attacker (on network)
    ↓
Sends Modbus TCP packet to port 5020
    ↓
Register modified in datastore (e.g., register 31 = 1)
    ↓
apply_modbus_commands() reads the register
    ↓
Global variable updated (MV301 = 1)
    ↓
update_physical_process() sees new state
    ↓
Physics simulates: "MV301 is open → drain tank"
    ↓
Tank level decreases (LIT401 drops)
    ↓
Sensors broadcast new values via Modbus
    ↓
Honeypot logs: "[ATTACK] Register 31 → LIT401 dropped to X"
    ↓
Attacker sees real-time feedback of their attack working
```

---

## Key Differences from Before

| Aspect | Before | Now |
|--------|--------|-----|
| **Attack Reception** | ✓ Registers modified | ✓ Registers modified |
| **Feedback Loop** | ✗ Commands ignored | ✓ Commands applied to physics |
| **Real-time Effect** | ✗ No change to plant | ✓ Plant responds immediately |
| **Forensics** | ✓ Alert logged | ✓ Full attack chain logged |
| **Realism** | ✗ Fake (unresponsive) | ✓ Real (like actual SCADA) |

---

## Running the System

### Step 1: Start the Digital Twin

```bash
python Twin.py
```

**Expected output:**
```
[STARTUP] Digital Twin initialization…
[STARTUP] Vulnerability: Zero-day attacks will directly affect plant state
[STARTUP] Mode: Real-time plant response to malicious Modbus commands

[INFO] Starting Modbus Digital Twin on port 5020...
```

The system is now listening for Modbus connections.

### Step 2: Run Attack Demonstrations

In another terminal:

```bash
python attack_example.py
```

This will show interactive menu:
```
Available attack demonstrations:

  1. Emergency Drain Attack
  2. Pump Overload Attack
  3. Sensor Spoofing Attack
  4. Combined Attack
  5. Run all attacks
  6. Exit
```

---

## Attack Scenarios Explained

### Attack 1: Emergency Drain
**Command:** `Register 31 = 1` (MV301 open)

**What happens:**
- Valve opens to drain Tank 4
- Physics engine sees: `if MV301 == 1: LIT401 -= 0.25` per tick
- Tank level drops rapidly in real-time
- Attacker can see it working

**Impact:** Operational disruption, water loss, potential safety hazard

---

### Attack 2: Pump Overload
**Command:** `Register 20 = 1` (P101 ON)

**What happens:**
- Raw water pump forced ON continuously
- Physics engine: `if P101_STATE == 1: LIT101 += 0.3` per tick
- Tank 1 fills rapidly, potential overflow at 100mm
- System can't stop it without control authority

**Impact:** Tank overflow, flood, damage to treatment plant

---

### Attack 3: Sensor Spoofing
**Command:** `Register 1 = 100` (fake LIT101 reading)

**What happens:**
- Sensor register shows false value
- Controller logic sees "tank is full" when it's not
- Controller makes wrong decisions based on false data
- Cascading logic errors

**Impact:** Loss of situational awareness, wrong control decisions

---

### Attack 4: Combined Attack
**Commands:** Multiple registers at once

**What happens:**
- Pump OFF + Valve OPEN
- Tank 1 depletes (no inflow)
- Tank 4 drains (forced outflow)
- System in critical state within seconds

**Impact:** Complete operational failure, safety violation

---

## Forensics & Logging

All attacks are logged to `attack_forensics.log`:

```
[SESSION START] 2026-03-29 15:32:14
================================================================================

[ATTACK DETECTED] 15:32:22 | Register 31 (Motor Valve 3 - Tank Drain) → 1
  └─ CONSEQUENCE: LIT101=49.5, LIT301=60.2, LIT401=54.75

[ATTACK DETECTED] 15:32:23 | Register 31 (Motor Valve 3 - Tank Drain) → 1
  └─ CONSEQUENCE: LIT101=49.3, LIT301=60.1, LIT401=54.50
```

The log shows:
1. **Exact timestamp** of attack
2. **Which register** was modified
3. **New value** written by attacker
4. **Physical consequences** in milliseconds

---

## Key Vulnerabilities Demonstrated

1. **No Authentication** - Anyone on the network can send commands
2. **No Authorization** - No check if sender is allowed to modify
3. **No Validation** - Commands executed immediately without verification
4. **No Encryption** - Modbus traffic visible to any sniffer
5. **No Redundancy** - Single command causes immediate effect
6. **Real-time Impact** - Attacker gets instant feedback

---

## Defense Recommendations

To make the system resilient:

- [ ] Add message authentication (HMAC/TLS)
- [ ] Implement role-based access control (RBAC)
- [ ] Add rate limiting on register writes
- [ ] Implement command validation rules
- [ ] Add redundant system with voting
- [ ] Monitor for anomalous command patterns
- [ ] Encrypt Modbus traffic (Modbus over TLS)
- [ ] Log all commands with cryptographic proof

---

## Testing Your Own Attacks

You can create custom attack scripts using the pymodbus library:

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient("localhost", 5020)
client.connect()

# Drain tank 4
client.write_register(31, 1)

# Disable pump 1
client.write_register(20, 0)

# Spoof temperature sensor
client.write_register(100, 999)

client.close()
```

---

## Files

- `Twin.py` - Digital twin with real-time attack response
- `attack_example.py` - Interactive attack demonstrations
- `attack_forensics.log` - Persistent attack log
- `DT_ASSESSMENT_REPORT.md` - Vulnerability assessment

---

## Summary

The digital twin now behaves like a **real SCADA system under attack**:
- ✅ Commands have immediate physical effect
- ✅ Attackers get real-time feedback
- ✅ Every action is forensically logged
- ✅ Cascading failures are possible
- ✅ Zero-day exploits are fully functional

This is a realistic testbed for understanding and defending against ICS/SCADA attacks.

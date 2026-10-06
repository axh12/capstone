from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusDeviceIdentification

import random
import threading
import time


# ------------------------------
# 1. GLOBAL SIMULATION VARIABLES
# ------------------------------
LIT101 = 50.0   # Tank level 1
LIT301 = 60.0
LIT401 = 55.0

FIT101 = 0.0    # Flow sensors
FIT301 = 0.0
FIT401 = 0.0

P101_STATE = 0  # Pump states
P102_STATE = 0
P301_STATE = 0

MV101 = 1       # Motor valves
MV301 = 1


# ------------------------------
# 2. MODBUS DATASTORE
# ------------------------------
from pymodbus.datastore import ModbusSequentialDataBlock

# Initialize holding registers (0-300) with default values
hr = ModbusSequentialDataBlock(0, [0] * 300)

store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [0] * 100),
    co=ModbusSequentialDataBlock(0, [0] * 100),
    hr=hr,
    ir=ModbusSequentialDataBlock(0, [0] * 100)
)

context = ModbusServerContext(slaves=store, single=True)


# ----------------------------------------------------------
# 3. SENSOR SIMULATION ENGINE (Simple SWaT Water Dynamics)
# ----------------------------------------------------------
def update_physical_process():
    global LIT101, LIT301, LIT401
    global FIT101, FIT301, FIT401
    global P101_STATE, P102_STATE, P301_STATE
    global MV101, MV301

    while True:

        # ----------------------
        # Tank Level Simulation
        # ----------------------
        if P101_STATE == 1:  # Pump fills Tank 1
            LIT101 = min(100, LIT101 + 0.3)
        else:
            LIT101 = max(0, LIT101 - 0.1)

        if P301_STATE == 1:  # Pump fills Tank 3
            LIT301 = min(100, LIT301 + 0.25)
        else:
            LIT301 = max(0, LIT301 - 0.15)

        if MV301 == 1:    # Valve drains Tank 4
            LIT401 = max(0, LIT401 - 0.25)
        else:
            LIT401 = min(100, LIT401 + 0.1)

        # ----------------------
        # Flow Logic
        # ----------------------
        FIT101 = 10 * P101_STATE + random.uniform(-0.2, 0.2)
        FIT301 = 8 * P301_STATE + random.uniform(-0.2, 0.2)
        FIT401 = 6 * MV301 + random.uniform(-0.2, 0.2)

        # ----------------------
        # WRITE TO MODBUS REGISTERS
        # ----------------------
        w = context[0].setValues

        # LIT (Tank Levels)
        w(3, 1,  [int(LIT101)])
        w(3, 2,  [int(LIT301)])
        w(3, 3,  [int(LIT401)])

        # FIT (Flows)
        w(3, 10, [int(FIT101)])
        w(3, 11, [int(FIT301)])
        w(3, 12, [int(FIT401)])

        # Actuators
        w(3, 20, [P101_STATE])
        w(3, 21, [P102_STATE])
        w(3, 22, [P301_STATE])

        w(3, 30, [MV101])
        w(3, 31, [MV301])

        # Add noisy values to registers 50-200 to mimic SWaT full plant
        for reg in range(50, 200):
            w(3, reg, [random.randint(0, 100)])

        time.sleep(1)  # Update rate 1 Hz


# ----------------------------------------------------------
# 4. COMMAND FEEDBACK LOOP — READS ATTACKER COMMANDS FROM MODBUS
# ----------------------------------------------------------
def apply_modbus_commands():
    """
    Reads actuator commands from Modbus registers (written by attacker or controller).
    Updates global variables to reflect those commands.
    This creates real-time feedback: attacker packet → register change → plant behavior change.
    """
    global P101_STATE, P102_STATE, P301_STATE, MV101, MV301

    while True:
        r = context[0].getValues

        # Read command registers that attackers would modify
        commands = {
            "P101": r(3, 20, 1)[0] if len(r(3, 20, 1)) > 0 else 0,
            "P102": r(3, 21, 1)[0] if len(r(3, 21, 1)) > 0 else 0,
            "P301": r(3, 22, 1)[0] if len(r(3, 22, 1)) > 0 else 0,
            "MV101": r(3, 30, 1)[0] if len(r(3, 30, 1)) > 0 else 0,
            "MV301": r(3, 31, 1)[0] if len(r(3, 31, 1)) > 0 else 0,
        }

        # Apply commands to global state — THIS IS WHERE ATTACK TAKES EFFECT
        P101_STATE = 1 if commands["P101"] else 0
        P102_STATE = 1 if commands["P102"] else 0
        P301_STATE = 1 if commands["P301"] else 0
        MV101 = 1 if commands["MV101"] else 0
        MV301 = 1 if commands["MV301"] else 0

        time.sleep(0.1)  # Check commands frequently


# ----------------------------------------------------------
# 5. ATTACK FORENSICS & HONEYPOT MONITORING
# ----------------------------------------------------------
def monitor_attacks():
    """
    Logs all register changes (attacker activity).
    Tracks cascading effects on plant state to show attack consequences.
    """
    print("[HONEYPOT] Attack monitoring started…\n")

    previous_values = {}
    previous_plant_state = {"LIT101": 50.0, "LIT301": 60.0, "LIT401": 55.0}

    attack_log = open("attack_forensics.log", "a")
    attack_log.write(f"\n{'='*80}\n[SESSION START] {time.strftime('%Y-%m-%d %H:%M:%S')}\n{'='*80}\n")

    while True:
        hr = context[0].getValues(3, 0, 300)
        current_plant_state = {
            "LIT101": float(hr[1]) if len(hr) > 1 else 0,
            "LIT301": float(hr[2]) if len(hr) > 2 else 0,
            "LIT401": float(hr[3]) if len(hr) > 3 else 0,
        }

        # Track register changes (attack indicator)
        for reg, val in enumerate(hr):
            if reg not in previous_values:
                previous_values[reg] = val

            if val != previous_values[reg]:
                # Determine if this is an actuator command register
                actuator_map = {
                    20: "P101 (Raw Water Pump)",
                    21: "P102 (Pump 2)",
                    22: "P301 (Lift Pump)",
                    30: "MV101 (Motor Valve 1)",
                    31: "MV301 (Motor Valve 3 - Tank Drain)",
                }

                if reg in actuator_map:
                    log_msg = f"\n[ATTACK DETECTED] {time.strftime('%H:%M:%S')} | Register {reg} ({actuator_map[reg]}) → {val}"
                    print(log_msg)
                    attack_log.write(log_msg + "\n")

                    # Show cascading effect
                    time.sleep(1.5)  # Let physics engine react
                    new_state = {
                        "LIT101": float(context[0].getValues(3, 1, 1)[0]) if len(context[0].getValues(3, 1, 1)) > 0 else 0,
                        "LIT301": float(context[0].getValues(3, 2, 1)[0]) if len(context[0].getValues(3, 2, 1)) > 0 else 0,
                        "LIT401": float(context[0].getValues(3, 3, 1)[0]) if len(context[0].getValues(3, 3, 1)) > 0 else 0,
                    }

                    consequence = f"  └─ CONSEQUENCE: LIT101={new_state['LIT101']:.1f}, LIT301={new_state['LIT301']:.1f}, LIT401={new_state['LIT401']:.1f}"
                    print(consequence)
                    attack_log.write(consequence + "\n")

                else:
                    log_msg = f"[INFO] Register {reg} modified → {val}"
                    print(log_msg)
                    attack_log.write(log_msg + "\n")

                previous_values[reg] = val

        attack_log.flush()
        time.sleep(0.5)


# ----------------------------------------------------------
# 6. START MODBUS TCP SERVER
# ----------------------------------------------------------
def start_server():
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'SWAT-DIGITAL-TWIN'
    identity.ProductName = 'SCADA-HONEYPOT'
    identity.ModelName = 'SWAT-PYTHON-TWIN'
    identity.MajorMinorRevision = '1.0'

    print("[INFO] Starting Modbus Digital Twin on port 5020...")

    from pymodbus.server import StartTcpServer
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", 5020))


# ----------------------------------------------------------
# 7. THREADS FOR SIMULATION + ATTACK FEEDBACK + FORENSICS + SERVER
# ----------------------------------------------------------
if __name__ == "__main__":
    print("[STARTUP] Digital Twin initialization…")
    print("[STARTUP] Vulnerability: Zero-day attacks will directly affect plant state")
    print("[STARTUP] Mode: Real-time plant response to malicious Modbus commands\n")
    
    threading.Thread(target=update_physical_process, daemon=True).start()
    threading.Thread(target=apply_modbus_commands, daemon=True).start()
    threading.Thread(target=monitor_attacks, daemon=True).start()
    start_server()

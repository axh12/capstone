"""Stage-1 telemetry adapters and an explicit Nano pump-1 command adapter.

Telemetry reads are the default. Physical writes require the separate
ArduinoNanoModbusForwarder and matching firmware acknowledgements.
"""
from __future__ import annotations

import json
import math
import re
import struct
import threading
import time
from typing import Any, Dict, Protocol


class Stage1ReadOnlyConnector(Protocol):
    def read_state(self) -> Dict[str, Any]: ...


class NullStage1Connector:
    """Safe default when no physical Stage 1 is configured."""
    def read_state(self) -> Dict[str, Any]:
        return {}


class ArduinoNanoSerialStage1Connector:
    """Read newline-delimited JSON telemetry from a Nano over USB serial.

    JSON mode expects ``water_level_mm`` (or ``distance_mm``) and
    ``outlet_flow_lpm`` (or ``outlet_flow_m3h``). The original Nano sketch's
    two-line ``Distance: N cm`` / ``Flow: N L/min`` output is supported by
    ``serial_format='arduino-text'``. Optional JSON
    binary ``inlet_pump_on`` / ``outlet_pump_on`` report physical relay state.
    Telemetry reads do not send commands. ``command_pump1`` is used only by
    the explicit physical-forwarding mode.
    """

    def __init__(self, device: str, empty_distance_mm: float | None = None, baudrate: int = 115200,
                 timeout_seconds: float = 5.0, serial_format: str = 'json'):
        if not device:
            raise ValueError("Serial device is required")
        if empty_distance_mm is not None and (
                not math.isfinite(empty_distance_mm) or empty_distance_mm <= 0):
            raise ValueError("Empty-tank distance must be positive and finite")
        if baudrate <= 0 or timeout_seconds <= 0:
            raise ValueError("Serial baud rate and timeout must be positive")
        if serial_format not in ('json', 'arduino-text'):
            raise ValueError('Unknown Nano serial format')
        self.device = device
        self.empty_distance_mm = float(empty_distance_mm) if empty_distance_mm is not None else None
        self.baudrate = baudrate
        self.timeout_seconds = timeout_seconds
        self.serial_format = serial_format
        self._serial = None
        self._lock = threading.RLock()
        self._command_sequence = 0

    def _open_serial(self) -> None:
        if self._serial is None:
            import serial
            self._serial = serial.Serial(self.device, baudrate=self.baudrate,
                                         timeout=self.timeout_seconds)

    def command_pump1(self, value: int) -> None:
        """Request a timed pump-1 override; return only after the Nano acknowledges it."""
        if type(value) is not int or value not in (0, 1):
            raise ValueError('Pump 1 command must be 0 or 1')
        with self._lock:
            self._open_serial()
            self._command_sequence = (self._command_sequence + 1) % 65536
            sequence = self._command_sequence
            self._serial.write(f'P1 {sequence} {value}\n'.encode('ascii'))
            self._serial.flush()
            expected = f'ACK P1 {sequence} {value}'
            deadline = time.monotonic() + self.timeout_seconds
            while time.monotonic() < deadline:
                line = self._serial.readline()
                if not line:
                    continue
                response = line.decode('ascii', errors='replace').strip()
                if response == expected:
                    return
                if response.startswith(f'ERR P1 {sequence} '):
                    raise RuntimeError(f'Nano rejected pump 1 command: {response}')
            raise TimeoutError('Nano did not acknowledge pump 1 command')

    def _decode(self, line: bytes) -> Dict[str, float | int]:
        try:
            record = json.loads(line.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError('Malformed Nano JSON telemetry') from error
        if not isinstance(record, dict):
            raise ValueError('Nano telemetry must be a JSON object')
        if ('water_level_mm' in record) == ('distance_mm' in record):
            raise ValueError('Nano must send exactly one water-level field')
        if ('outlet_flow_lpm' in record) == ('outlet_flow_m3h' in record):
            raise ValueError('Nano must send exactly one outlet-flow field')
        readings = {}
        for field in ('water_level_mm', 'distance_mm', 'outlet_flow_lpm', 'outlet_flow_m3h'):
            if field not in record:
                continue
            value = record[field]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f'Invalid Nano {field}')
            readings[field] = float(value)
        if 'water_level_mm' in readings:
            level_mm = readings['water_level_mm']
        else:
            if self.empty_distance_mm is None:
                raise ValueError('Distance telemetry requires empty_distance_mm calibration')
            if not 0 <= readings['distance_mm'] <= self.empty_distance_mm:
                raise ValueError('Nano distance is outside calibrated tank range')
            level_mm = self.empty_distance_mm - readings['distance_mm']
        flow_m3h = (readings['outlet_flow_lpm'] * 0.06 if 'outlet_flow_lpm' in readings
                    else readings['outlet_flow_m3h'])
        if level_mm < 0:
            raise ValueError('Nano water level must be nonnegative')
        if flow_m3h < 0:
            raise ValueError('Nano outlet flow must be nonnegative')
        state: Dict[str, float | int] = {
            'LIT101': level_mm,
            'FIT201': flow_m3h,
        }
        for source, target in (('inlet_pump_on', 'mv101'), ('outlet_pump_on', 'p101')):
            if source in record:
                if type(record[source]) is not int or record[source] not in (0, 1):
                    raise ValueError(f'Invalid Nano {source}')
                state[target] = record[source]
        return state

    def _decode_arduino_pair(self, distance_line: bytes, flow_line: bytes) -> Dict[str, float | int]:
        try:
            distance_text = distance_line.decode('ascii').strip()
            flow_text = flow_line.decode('ascii').strip()
        except UnicodeDecodeError as error:
            raise ValueError('Malformed Nano text telemetry') from error
        distance_match = re.fullmatch(r'(?:(?:Distance|istance|stance):\s*)?(-?\d+)\s*cm', distance_text)
        flow_match = re.fullmatch(r'Flow:\s*(\d+(?:\.\d+)?)\s*L/min', flow_text)
        if distance_match is None or flow_match is None:
            raise ValueError('Expected consecutive Nano distance and flow lines')
        distance_cm = int(distance_match.group(1))
        if distance_cm in (-1, 99):
            raise ValueError('Nano ultrasonic sensor returned a no-echo reading')
        if distance_cm < 0:
            raise ValueError('Nano distance must be nonnegative')
        flow_lpm = float(flow_match.group(1))
        if self.empty_distance_mm is None:
            return {'distance_cm': float(distance_cm), 'FIT201': flow_lpm * 0.06}
        state = self._decode(json.dumps({
            'distance_mm': distance_cm * 10,
            'outlet_flow_lpm': flow_lpm,
        }).encode('ascii'))
        state['distance_cm'] = float(distance_cm)
        return state

    def read_state(self) -> Dict[str, float | int]:
        with self._lock:
            self._open_serial()
            deadline = time.monotonic() + self.timeout_seconds
            latest = None
            distance_line = None
            saw_no_echo = False
            malformed_line = None
            while time.monotonic() < deadline:
                line = self._serial.readline()
                if not line:
                    break
                if self.serial_format == 'arduino-text' and not line.strip():
                    continue
                if self.serial_format == 'arduino-text' and line.startswith((b'ACK P1 ', b'ERR P1 ')):
                    continue
                if self.serial_format == 'json':
                    latest = self._decode(line)
                    if not getattr(self._serial, 'in_waiting', 0):
                        return latest
                elif (line.startswith((b'Distance:', b'istance:', b'stance:'))
                      or re.fullmatch(rb'-?\d+\s*cm\s*', line)):
                    distance_line = line
                elif line.startswith(b'Flow:') and distance_line is not None:
                    try:
                        latest = self._decode_arduino_pair(distance_line, line)
                    except ValueError as error:
                        if 'no-echo' not in str(error):
                            raise
                        saw_no_echo = True
                        distance_line = None
                        continue
                    if not getattr(self._serial, 'in_waiting', 0):
                        return latest
                    distance_line = None
                elif line.startswith(b'Flow:') and distance_line is None:
                    # A serial connection can start between the two lines of
                    # a sample. Wait for the next complete distance/flow pair.
                    continue
                else:
                    # A USB reconnection or a read timeout can leave a partial
                    # text line in the stream. Discard it and wait for a fresh
                    # Distance/Flow pair; never turn a fragment into state.
                    malformed_line = line[:80]
                    distance_line = None
                    continue
            if latest is not None:
                return latest
            if saw_no_echo:
                raise ValueError('Nano ultrasonic sensor returned only no-echo readings')
            if malformed_line is not None:
                raise ValueError(f'Unexpected Nano text telemetry line: {malformed_line!r}')
            raise TimeoutError('No Nano telemetry received over serial')

    def close(self) -> None:
        with self._lock:
            if self._serial is not None:
                self._serial.close()
                self._serial = None


class ArduinoNanoModbusForwarder:
    """Forward only the rig's supported pump-1 write over the shared serial link.

    The Nano has no Modbus server. An acknowledged serial command is converted
    to a Modbus FC06 success echo; every other function/register is rejected.
    """

    def __init__(self, connector: ArduinoNanoSerialStage1Connector):
        self.connector = connector

    def __call__(self, request: bytes) -> bytes:
        if len(request) != 12 or request[7] != 6:
            function = request[7] if len(request) > 7 else 0
            return self._exception(request, function, 1)
        register, value = struct.unpack('>HH', request[8:12])
        if register != 30:
            return self._exception(request, 6, 2)
        if value not in (0, 1):
            return self._exception(request, 6, 3)
        self.connector.command_pump1(value)
        return request

    @staticmethod
    def _exception(request: bytes, function: int, code: int) -> bytes:
        if len(request) < 7:
            raise ValueError('Truncated Modbus request')
        return request[:4] + struct.pack('>H', 3) + request[6:7] + bytes([function | 0x80, code])


class ModbusReadOnlyStage1Connector:
    """Read holding registers from a reference plant; never writes commands."""

    def __init__(self, host: str, port: int = 502, unit: int = 1,
                 register_map: Dict[str, int] | None = None):
        self.host, self.port, self.unit = host, port, unit
        self.register_map = register_map or {}

    def read_state(self) -> Dict[str, Any]:
        try:
            from pymodbus.client import ModbusTcpClient
        except ImportError:
            from pymodbus.client.sync import ModbusTcpClient
        client = ModbusTcpClient(self.host, port=self.port)
        try:
            if not client.connect():
                raise ConnectionError(f"Unable to connect to Stage 1 at {self.host}:{self.port}")
            state: Dict[str, Any] = {}
            for name, address in self.register_map.items():
                try:
                    response = client.read_holding_registers(address, count=1, unit=self.unit)
                except TypeError:
                    response = client.read_holding_registers(address, count=1, slave=self.unit)
                if response.isError():
                    raise RuntimeError(f"Stage 1 read failed for {name}: {response}")
                state[name] = response.registers[0]
            return state
        finally:
            client.close()

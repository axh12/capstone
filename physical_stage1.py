"""Read-only Stage-1 synchronization adapters.

No method in this module writes to the physical plant. External/attacker
commands therefore cannot be forwarded through this interface.
"""
from __future__ import annotations

import json
import math
import re
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
    Serial input is read-only: this connector never sends commands to Nano.
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
        distance_match = re.fullmatch(r'Distance:\s*(\d+)\s*cm', distance_text)
        flow_match = re.fullmatch(r'Flow:\s*(\d+(?:\.\d+)?)\s*L/min', flow_text)
        if distance_match is None or flow_match is None:
            raise ValueError('Expected consecutive Nano distance and flow lines')
        distance_cm = int(distance_match.group(1))
        if distance_cm == 99:
            raise ValueError('Nano ultrasonic sensor returned its no-echo sentinel (99 cm)')
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
            if self._serial is None:
                import serial
                self._serial = serial.Serial(self.device, baudrate=self.baudrate,
                                             timeout=self.timeout_seconds)
            deadline = time.monotonic() + self.timeout_seconds
            latest = None
            distance_line = None
            while time.monotonic() < deadline:
                line = self._serial.readline()
                if not line:
                    break
                if self.serial_format == 'json':
                    latest = self._decode(line)
                    if not getattr(self._serial, 'in_waiting', 0):
                        return latest
                elif line.startswith(b'Distance:'):
                    distance_line = line
                elif line.startswith(b'Flow:') and distance_line is not None:
                    latest = self._decode_arduino_pair(distance_line, line)
                    if not getattr(self._serial, 'in_waiting', 0):
                        return latest
                    distance_line = None
                else:
                    raise ValueError('Unexpected Nano text telemetry line')
            if latest is not None:
                return latest
            raise TimeoutError('No Nano telemetry received over serial')

    def close(self) -> None:
        with self._lock:
            if self._serial is not None:
                self._serial.close()
                self._serial = None


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

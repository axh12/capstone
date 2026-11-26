"""Stage-1 synchronization and mediated command/state exchange.

The default connector is read-only. Bidirectional Modbus communication is
available through ``ModbusBidirectionalStage1Connector``, but it requires
explicit state/command register maps and ``enable_writeback=True``.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Mapping, Protocol


class Stage1Connector(Protocol):
    def read_state(self) -> Dict[str, Any]: ...
    def read_commands(self) -> Dict[str, int]: ...
    def publish_state(self, state: Mapping[str, Any]) -> None: ...


class NullStage1Connector:
    """Safe default when no physical Stage 1 is configured."""

    def read_state(self) -> Dict[str, Any]:
        return {}

    def read_commands(self) -> Dict[str, int]:
        return {}

    def publish_state(self, state: Mapping[str, Any]) -> None:
        return None


class ArduinoSerialStage1Connector:
    """Read Arduino telemetry over USB serial.

    The connector is deliberately read-only unless ``enable_actuation`` is
    explicitly set.  The Arduino firmware must implement the line protocol
    used here (``STATUS`` and ``PUMP ON/OFF``).  No command is sent during
    construction or during a normal state read.
    """

    _DISTANCE = re.compile(r"Distance:\s*(-?\d+(?:\.\d+)?)\s*cm", re.I)
    _FLOW = re.compile(r"Flow:\s*(-?\d+(?:\.\d+)?)\s*L/(?:min|m)", re.I)
    _PUMP = re.compile(r"Pump:\s*(ON|OFF)", re.I)

    def __init__(self, port: str, baudrate: int = 9600, timeout: float = 0.5,
                 *, enable_actuation: bool = False, startup_wait: float = 3.0):
        self.port = port
        self.baudrate = int(baudrate)
        self.timeout = float(timeout)
        self.enable_actuation = bool(enable_actuation)
        self.startup_wait = max(0.0, float(startup_wait))

    def _serial(self):
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("pyserial is required for Arduino serial communication") from exc
        # Open with DTR already deasserted.  On Uno-compatible boards a DTR
        # transition from a USB-UART adapter commonly resets the MCU, which
        # would also make the LCD show its startup screen on every STATUS call.
        connection = serial.Serial(port=None, baudrate=self.baudrate,
                                   timeout=self.timeout, dsrdtr=False,
                                   rtscts=False)
        connection.dtr = False
        connection.rts = False
        connection.port = self.port
        connection.open()
        return connection

    @classmethod
    def _parse_line(cls, line: str, state: Dict[str, Any]) -> None:
        if match := cls._DISTANCE.search(line):
            state["LIT101"] = float(match.group(1))
        if match := cls._FLOW.search(line):
            state["FIT101"] = float(match.group(1))
        if match := cls._PUMP.search(line):
            state["p101"] = 1 if match.group(1).upper() == "ON" else 0

    def read_state(self) -> Dict[str, Any]:
        state: Dict[str, Any] = {}
        with self._serial() as connection:
            # Opening an Uno-compatible serial port commonly toggles DTR and
            # resets the board. Wait for setup() before requesting telemetry.
            if self.startup_wait:
                time.sleep(self.startup_wait)
            if hasattr(connection, "reset_input_buffer"):
                connection.reset_input_buffer()
            connection.write(b"STATUS\n")
            connection.flush()
            deadline = time.monotonic() + max(self.timeout, 2.0)
            while time.monotonic() < deadline:
                raw = connection.readline()
                if not raw:
                    break
                self._parse_line(raw.decode("utf-8", errors="replace"), state)
        return state

    def read_commands(self) -> Dict[str, int]:
        return {}

    def publish_state(self, state: Mapping[str, Any]) -> None:
        return None

    def set_pump(self, enabled: bool) -> None:
        """Send an explicit pump command only when actuation is enabled."""
        if not self.enable_actuation:
            raise PermissionError(
                "Physical actuation is disabled; pass enable_actuation=True only after safety checks"
            )
        command = b"PUMP ON\n" if enabled else b"PUMP OFF\n"
        self._send(command)

    def set_remote_control(self, enabled: bool) -> None:
        """Enable/disable firmware remote mode; disabled mode also turns pump off."""
        if not self.enable_actuation:
            raise PermissionError(
                "Physical actuation is disabled; pass enable_actuation=True only after safety checks"
            )
        self._send(b"REMOTE ENABLE\n" if enabled else b"REMOTE DISABLE\n")

    def _send(self, command: bytes) -> None:
        with self._serial() as connection:
            connection.write(command)
            connection.flush()


class ModbusReadOnlyStage1Connector:
    """Read holding registers from a reference plant; never writes."""

    def __init__(self, host: str, port: int = 502, unit: int = 1,
                 register_map: Dict[str, int] | None = None):
        self.host, self.port, self.unit = host, port, unit
        self.register_map = register_map or {}

    def _client(self):
        try:
            from pymodbus.client import ModbusTcpClient
        except ImportError:
            from pymodbus.client.sync import ModbusTcpClient
        return ModbusTcpClient(self.host, port=self.port)

    def _read_one(self, client: Any, address: int) -> int:
        try:
            response = client.read_holding_registers(address, count=1, unit=self.unit)
        except TypeError:
            response = client.read_holding_registers(address, count=1, slave=self.unit)
        if response.isError():
            raise RuntimeError(f"Stage 1 read failed at register {address}: {response}")
        return int(response.registers[0])

    def read_state(self) -> Dict[str, Any]:
        client = self._client()
        try:
            if not client.connect():
                raise ConnectionError(f"Unable to connect to Stage 1 at {self.host}:{self.port}")
            return {name: self._read_one(client, address)
                    for name, address in self.register_map.items()}
        finally:
            client.close()

    def read_commands(self) -> Dict[str, int]:
        return {}

    def publish_state(self, state: Mapping[str, Any]) -> None:
        return None


class ModbusBidirectionalStage1Connector(ModbusReadOnlyStage1Connector):
    """Mediated bidirectional Modbus interface for a real Stage 1.

    State registers are dedicated status/telemetry registers written by the
    Twin. Command registers are polled and applied to the Twin only when their
    names are allowlisted. The two register maps must not overlap.
    """

    def __init__(
        self,
        host: str,
        port: int = 502,
        unit: int = 1,
        register_map: Dict[str, int] | None = None,
        *,
        state_register_map: Dict[str, int] | None = None,
        command_register_map: Dict[str, int] | None = None,
        command_allowlist: set[str] | None = None,
        enable_writeback: bool = False,
    ):
        super().__init__(host, port, unit, register_map)
        self.state_register_map = dict(state_register_map or {})
        self.command_register_map = dict(command_register_map or {})
        self.command_allowlist = set(command_allowlist or self.command_register_map)
        self.enable_writeback = bool(enable_writeback)
        overlap = set(self.state_register_map.values()) & set(self.command_register_map.values())
        if overlap:
            raise ValueError(f"State and command register maps overlap: {sorted(overlap)}")
        unknown = self.command_allowlist - set(self.command_register_map)
        if unknown:
            raise ValueError(f"Allowlisted commands have no register: {sorted(unknown)}")
        if self.enable_writeback and not self.state_register_map:
            raise ValueError("State register map is required when writeback is enabled")

    def read_commands(self) -> Dict[str, int]:
        if not self.command_register_map:
            return {}
        client = self._client()
        try:
            if not client.connect():
                raise ConnectionError(f"Unable to connect to Stage 1 at {self.host}:{self.port}")
            return {
                name: self._read_one(client, address)
                for name, address in self.command_register_map.items()
                if name in self.command_allowlist
            }
        finally:
            client.close()

    def publish_state(self, state: Mapping[str, Any]) -> None:
        if not self.enable_writeback or not self.state_register_map:
            return
        client = self._client()
        try:
            if not client.connect():
                raise ConnectionError(f"Unable to connect to Stage 1 at {self.host}:{self.port}")
            for name, address in self.state_register_map.items():
                if name not in state:
                    continue
                value = int(round(float(state[name])))
                if not 0 <= value <= 65535:
                    raise ValueError(f"State value for {name} is outside Modbus range: {value}")
                try:
                    response = client.write_register(address, value, unit=self.unit)
                except TypeError:
                    response = client.write_register(address, value, slave=self.unit)
                if response.isError():
                    raise RuntimeError(f"Stage 1 state publish failed for {name}: {response}")
        finally:
            client.close()

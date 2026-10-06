"""Read-only Stage-1 synchronization adapters.

No method in this module writes to the physical plant. External/attacker
commands therefore cannot be forwarded through this interface.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Protocol


class Stage1ReadOnlyConnector(Protocol):
    def read_state(self) -> Dict[str, Any]: ...


class NullStage1Connector:
    """Safe default when no physical Stage 1 is configured."""
    def read_state(self) -> Dict[str, Any]:
        return {}


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

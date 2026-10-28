"""Loopback-only mock SCADA holding registers for gateway integration tests."""
import argparse
import json
import socketserver
import struct
import threading
from copy import deepcopy

from modbus_gateway import receive_frame, response_frame, sensor_registers, STAGE1_ACTUATORS


class MockScadaServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    ACTUATOR_REGISTERS = {"p101": 20, "p201": 21, "p301": 22,
                          "p203": 23, "mv101": 30, "mv201": 31}

    def __init__(self, address=("127.0.0.1", 15020)):
        if address[0] != "127.0.0.1":
            raise ValueError("Mock SCADA must listen on loopback")
        self.registers = {1: 500, 2: 600, 3: 800, 10: 0, 11: 0, 12: 0,
                          20: 0, 21: 0, 22: 0, 23: 0, 30: 0, 31: 0}
        self.received = []
        self.safety_events = []
        self.lock = threading.Lock()
        self.plant = None
        super().__init__(address, MockHandler)

    def initialize_plant(self, twin):
        """Copy the initial plant; only received writes advance this mock copy."""
        with self.lock:
            self.plant = deepcopy(twin)
            if twin.params.stage1_topology == 'swat_stage1':
                self.ACTUATOR_REGISTERS = {name: register for register, name in STAGE1_ACTUATORS.items()}
                self.registers = {}
            self._refresh_registers()

    def _refresh_registers(self):
        state = self.plant.snapshot()
        self.registers.update(sensor_registers(state))
        self.registers.update({register: int(state[name])
                               for name, register in self.ACTUATOR_REGISTERS.items()})

    def apply_emergency_actions(self, actions):
        """Model an out-of-band safety controller in this mock only."""
        updates = {}
        for actuator, value in actions.items():
            if actuator not in self.ACTUATOR_REGISTERS or value not in (0, 1):
                raise ValueError("Unsupported mock safety action")
            updates[self.ACTUATOR_REGISTERS[actuator]] = value
        with self.lock:
            self.registers.update(updates)
            if self.plant is not None:
                self.plant.apply_actions(actions)
                self._refresh_registers()
            self.safety_events.append(dict(updates))
        print(json.dumps({"component": "MOCK_SCADA_SAFETY", "registers": updates}),
              flush=True)
        return updates

    def respond(self, request):
        function = request[7]
        with self.lock:
            self.received.append(request)
            if function not in (3, 6):
                return response_frame(request, bytes([function | 0x80, 1]))
            if len(request) != 12:
                return response_frame(request, bytes([function | 0x80, 3]))
            address, value = struct.unpack(">HH", request[8:12])
            print(json.dumps({"component": "MOCK_SCADA", "function": function,
                              "register": address, "value_or_count": value}), flush=True)
            if function == 6:
                if address not in self.ACTUATOR_REGISTERS.values():
                    return response_frame(request, b"\x86\x02")
                if value not in (0, 1):
                    return response_frame(request, b"\x86\x03")
                self.registers[address] = value
                if self.plant is not None:
                    actuator = next(name for name, register in self.ACTUATOR_REGISTERS.items()
                                    if register == address)
                    self.plant.apply_actions({actuator: value})
                    self.plant.step()
                    self._refresh_registers()
                return request
            if not 1 <= value <= 125:
                return response_frame(request, b"\x83\x03")
            if any(key not in self.registers for key in range(address, address + value)):
                return response_frame(request, b"\x83\x02")
            values = [self.registers[key] for key in range(address, address + value)]
            return response_frame(request, bytes([3, 2 * value]) + struct.pack(">" + "H" * value, *values))


class MockHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        while True:
            try:
                self.request.sendall(self.server.respond(receive_frame(self.request)))
            except (EOFError, ValueError, OSError):
                return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=15020)
    args = parser.parse_args()
    with MockScadaServer(("127.0.0.1", args.port)) as server:
        print(f"Mock SCADA listening on 127.0.0.1:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

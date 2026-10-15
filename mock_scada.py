"""Loopback-only mock SCADA holding registers for gateway integration tests."""
import argparse
import json
import socketserver
import struct
import threading

from modbus_gateway import receive_frame, response_frame


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
        super().__init__(address, MockHandler)

    def apply_emergency_actions(self, actions):
        """Model an out-of-band safety controller in this mock only."""
        updates = {}
        for actuator, value in actions.items():
            if actuator not in self.ACTUATOR_REGISTERS or value not in (0, 1):
                raise ValueError("Unsupported mock safety action")
            updates[self.ACTUATOR_REGISTERS[actuator]] = value
        with self.lock:
            self.registers.update(updates)
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
                if address not in (20, 21, 22, 23, 30, 31):
                    return response_frame(request, b"\x86\x02")
                if value not in (0, 1):
                    return response_frame(request, b"\x86\x03")
                self.registers[address] = value
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

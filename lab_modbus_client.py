"""Standard-library Modbus lab client, usable on Kali without dependencies."""
import argparse
import socket
import struct


def receive_exact(connection, size):
    result = b""
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EOFError("Incomplete response")
        result += chunk
    return result


def exchange(host, port, function, address, value):
    request = struct.pack(">HHHBBHH", 1, 0, 6, 1, function, address, value)
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(request)
        header = receive_exact(connection, 7)
        length = struct.unpack(">H", header[4:6])[0]
        if header[:4] != request[:4] or header[6] != 1 or not 2 <= length <= 254:
            raise ValueError("Invalid response header")
        pdu = receive_exact(connection, length - 1)
    if pdu[0] & 0x80:
        raise RuntimeError(f"Modbus exception: {pdu.hex()}")
    if function == 6:
        if header + pdu != request:
            raise ValueError("Write echo mismatch")
        print(f"Write acknowledged: register {address} = {value}")
    else:
        if pdu[0] != 3 or len(pdu) != 2 + 2 * value or pdu[1] != 2 * value:
            raise ValueError("Invalid read response")
        print(f"Register {address}: {struct.unpack('>H', pdu[2:4])[0]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--case", choices=("normal", "attack", "read"), required=True)
    args = parser.parse_args()
    function, address, value = {"normal": (6, 30, 1), "attack": (6, 20, 1), "read": (3, 20, 1)}[args.case]
    exchange(args.host, args.port, function, address, value)

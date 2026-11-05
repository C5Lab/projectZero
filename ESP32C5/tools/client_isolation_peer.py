#!/usr/bin/env python3
"""Owned, authenticated UDP peer for the JanOS client-isolation audit."""

import argparse
from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import struct
import sys
import threading
import time


JISO_MAGIC = 0x4A49534F
JISO_VERSION = 1
JISO_CHALLENGE = 1
JISO_REPLY = 2
JISO_TOKEN_BYTES = 16
JISO_NONCE_BYTES = 16
JISO_AUTHENTICATED_BYTES = 36
JISO_PACKET_BYTES = 52
DEFAULT_PORT = 48731
MIN_PORT = 1024
MAX_PORT = 65535
REPLAY_WINDOW = 64

_PREFIX = struct.Struct(">IBBHQI16s")


@dataclass(frozen=True)
class Message:
    type: int
    run_id: int
    sequence: int
    nonce: bytes


def _not_all_zero(value):
    return any(value)


def secure_zero(value):
    if isinstance(value, bytearray):
        for index in range(len(value)):
            value[index] = 0


def parse_token(value):
    if len(value) != JISO_TOKEN_BYTES * 2:
        raise argparse.ArgumentTypeError("token must be exactly 32 hex characters")
    try:
        token = bytearray.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("token must be exactly 32 hex characters") from error
    if not _not_all_zero(token):
        raise argparse.ArgumentTypeError("token must not be all zero")
    return token


def parse_bind(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError("bind must be a numeric IPv4 address") from error
    if address.is_multicast or address == ipaddress.IPv4Address("255.255.255.255"):
        raise argparse.ArgumentTypeError("bind must be a unicast IPv4 address or 0.0.0.0")
    return str(address)


def parse_port(value):
    try:
        port = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if port < MIN_PORT or port > MAX_PORT:
        raise argparse.ArgumentTypeError("port must be in 1024..65535")
    return port


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Owned JISO/1 UDP peer for JanOS client-isolation audits")
    parser.add_argument("--bind", type=parse_bind, default="0.0.0.0")
    parser.add_argument("--port", type=parse_port, default=DEFAULT_PORT)
    parser.add_argument("--token", type=parse_token)
    return parser.parse_args(argv)


def _token_valid(token):
    return token is not None and len(token) == JISO_TOKEN_BYTES and _not_all_zero(token)


def encode_message(message_type, run_id, sequence, nonce, token):
    if message_type not in (JISO_CHALLENGE, JISO_REPLY):
        raise ValueError("invalid JISO/1 message type")
    if not isinstance(run_id, int) or not 0 <= run_id <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("invalid JISO/1 run id")
    if not isinstance(sequence, int) or not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError("invalid JISO/1 sequence")
    if nonce is None or len(nonce) != JISO_NONCE_BYTES or not _not_all_zero(nonce):
        raise ValueError("invalid JISO/1 nonce")
    if not _token_valid(token):
        raise ValueError("invalid JISO/1 token")

    prefix = _PREFIX.pack(
        JISO_MAGIC, JISO_VERSION, message_type, 0,
        run_id, sequence, bytes(nonce))
    tag = hmac.new(token, prefix, hashlib.sha256).digest()[:16]
    return prefix + tag


def decode_message(packet, token):
    if not isinstance(packet, bytes) or len(packet) != JISO_PACKET_BYTES:
        return None
    if not _token_valid(token):
        return None
    prefix = packet[:JISO_AUTHENTICATED_BYTES]
    expected = hmac.new(token, prefix, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(packet[JISO_AUTHENTICATED_BYTES:], expected):
        return None
    try:
        magic, version, message_type, reserved, run_id, sequence, nonce = \
            _PREFIX.unpack(prefix)
    except struct.error:
        return None
    if (magic != JISO_MAGIC or version != JISO_VERSION or reserved != 0 or
            message_type not in (JISO_CHALLENGE, JISO_REPLY) or
            not _not_all_zero(nonce)):
        return None
    return Message(message_type, run_id, sequence, nonce)


class PeerEngine:
    """Validate challenges and emit at most one same-size reply per input."""

    def __init__(self, token, evidence_write=print, monotonic_ns=time.monotonic_ns):
        if not _token_valid(token):
            raise ValueError("invalid JISO/1 token")
        self._token = bytearray(token)
        self._evidence_write = evidence_write
        self._monotonic_ns = monotonic_ns
        self._recent = deque(maxlen=REPLAY_WINDOW)
        self.bound_run_id = None

    def _emit(self, message, address, valid, replied):
        message_type = None
        run_id = None
        sequence = None
        if message is not None:
            message_type = "challenge" if message.type == JISO_CHALLENGE else "reply"
            run_id = f"{message.run_id:016X}"
            sequence = message.sequence
        record = {
            "monotonic_ms": self._monotonic_ns() // 1_000_000,
            "replied": replied,
            "run": run_id,
            "sequence": sequence,
            "source_ip": address[0],
            "source_port": address[1],
            "type": message_type,
            "valid": valid,
        }
        self._evidence_write(
            "[ISO_PEER/1] " + json.dumps(
                record, sort_keys=True, separators=(",", ":")))

    def handle_datagram(self, packet, address, reply_write):
        message = decode_message(packet, self._token)
        if message is None:
            self._emit(None, address, False, False)
            return False
        if message.type != JISO_CHALLENGE:
            self._emit(message, address, True, False)
            return False
        if self.bound_run_id is None:
            self.bound_run_id = message.run_id
        if message.run_id != self.bound_run_id:
            self._emit(message, address, True, False)
            return False

        replay_key = (address[0], address[1], message.run_id,
                      message.sequence, message.nonce)
        if replay_key in self._recent:
            self._emit(message, address, True, False)
            return False
        reply = encode_message(
            JISO_REPLY, message.run_id, message.sequence,
            message.nonce, self._token)
        try:
            sent = reply_write(reply, address)
            if sent is not None and sent != len(reply):
                raise OSError("short UDP send")
        except OSError:
            self._emit(message, address, True, False)
            raise
        self._recent.append(replay_key)
        self._emit(message, address, True, True)
        return True

    def close(self):
        secure_zero(self._token)
        self._recent.clear()
        self.bound_run_id = None


def serve_peer(bind, port, token, evidence_write=print, stop_event=None,
               ready=None):
    engine = PeerEngine(token, evidence_write=evidence_write)
    udp = None
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((bind, port))
        udp.settimeout(0.1)
        if ready is not None:
            ready.put(udp.getsockname()[1])
        while stop_event is None or not stop_event.is_set():
            try:
                packet, source = udp.recvfrom(JISO_PACKET_BYTES + 1)
            except socket.timeout:
                continue
            engine.handle_datagram(packet, source, udp.sendto)
    finally:
        if udp is not None:
            udp.close()
        engine.close()


def _new_token():
    while True:
        token = bytearray(secrets.token_bytes(JISO_TOKEN_BYTES))
        if _not_all_zero(token):
            return token


def main(argv=None):
    args = parse_args(argv)
    token = args.token if args.token is not None else _new_token()
    if args.token is None:
        print(f"[ISO_PEER_TOKEN/1] {bytes(token).hex().upper()}",
              file=sys.stderr, flush=True)
    try:
        serve_peer(args.bind, args.port, token)
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("client_isolation_peer: socket error", file=sys.stderr)
        return 1
    finally:
        secure_zero(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

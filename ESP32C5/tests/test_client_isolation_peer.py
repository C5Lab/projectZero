"""Host tests for the owned JISO/1 UDP peer."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import hashlib
import hmac
import json
from pathlib import Path
import queue
import socket
import sys
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import client_isolation_peer as peer  # noqa: E402


TOKEN_HEX = "00112233445566778899AABBCCDDEEFF"
TOKEN = bytes.fromhex(TOKEN_HEX)
NONCE = bytes(range(0x10, 0x20))
RUN_ID = 0x0102030405060708
SEQUENCE = 0x11223344
KAT_PACKET_HEX = (
    "4A49534F01010000010203040506070811223344"
    "101112131415161718191A1B1C1D1E1F"
    "E4378204C52F13E67669BB844F5981A7"
)


def evidence_payload(line):
    prefix = "[ISO_PEER/1] "
    if not line.startswith(prefix):
        raise AssertionError(line)
    return json.loads(line[len(prefix):])


class CodecAndCliTest(unittest.TestCase):
    def test_codec_matches_independent_c_known_answer(self):
        packet = peer.encode_message(
            peer.JISO_CHALLENGE, RUN_ID, SEQUENCE, NONCE, TOKEN)
        self.assertEqual(packet.hex().upper(), KAT_PACKET_HEX)
        decoded = peer.decode_message(packet, TOKEN)
        self.assertEqual(decoded.type, peer.JISO_CHALLENGE)
        self.assertEqual(decoded.run_id, RUN_ID)
        self.assertEqual(decoded.sequence, SEQUENCE)
        self.assertEqual(decoded.nonce, NONCE)

        reply = peer.encode_message(
            peer.JISO_REPLY, RUN_ID, SEQUENCE, NONCE, TOKEN)
        decoded_reply = peer.decode_message(reply, TOKEN)
        self.assertEqual(decoded_reply.type, peer.JISO_REPLY)
        self.assertEqual(decoded_reply.nonce, NONCE)

    def test_codec_rejects_malformed_or_unauthenticated_input(self):
        packet = peer.encode_message(
            peer.JISO_CHALLENGE, RUN_ID, SEQUENCE, NONCE, TOKEN)
        rejected = [
            b"",
            packet[:-1],
            packet + b"x",
            bytes([packet[0] ^ 1]) + packet[1:],
            packet[:6] + b"\x01\x00" + packet[8:],
            packet[:20] + (b"\x00" * 16) + packet[36:],
            packet[:-1] + bytes([packet[-1] ^ 1]),
        ]
        for candidate in rejected:
            with self.subTest(length=len(candidate), packet=candidate[:8].hex()):
                self.assertIsNone(peer.decode_message(candidate, TOKEN))
        self.assertIsNone(peer.decode_message(packet, bytes.fromhex("10" * 16)))

    def test_cli_defaults_and_strict_validation(self):
        args = peer.parse_args([])
        self.assertEqual(args.bind, "0.0.0.0")
        self.assertEqual(args.port, 48731)
        self.assertIsNone(args.token)

        args = peer.parse_args([
            "--bind", "192.0.2.20", "--port", "49152",
            "--token", TOKEN_HEX.lower(),
        ])
        self.assertEqual(args.bind, "192.0.2.20")
        self.assertEqual(args.port, 49152)
        self.assertEqual(args.token, TOKEN)

        invalid_argv = [
            ["--bind", "localhost"],
            ["--bind", "2001:db8::1"],
            ["--port", "0"],
            ["--port", "1023"],
            ["--port", "65536"],
            ["--token", "00" * 15],
            ["--token", "GG" * 16],
            ["--token", "00" * 16],
        ]
        for argv in invalid_argv:
            with self.subTest(argv=argv), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    peer.parse_args(argv)

    def test_main_prints_only_generated_token_and_handles_shutdown_errors(self):
        generated = bytes.fromhex("A1" * 16)
        out = StringIO()
        err = StringIO()
        with mock.patch.object(peer, "serve_peer", side_effect=KeyboardInterrupt), \
                mock.patch.object(peer.secrets, "token_bytes", return_value=generated), \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(peer.main([]), 0)
        combined = out.getvalue() + err.getvalue()
        self.assertEqual(combined.count(generated.hex().upper()), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(
            err.getvalue(),
            f"[ISO_PEER_TOKEN/1] {generated.hex().upper()}\n")
        for line in combined.splitlines():
            if line.startswith("[ISO_PEER/1] "):
                record = evidence_payload(line)
                serialized = json.dumps(record).upper()
                self.assertNotIn(generated.hex().upper(), serialized)
                self.assertNotIn("TOKEN", record)
                self.assertNotIn("NONCE", record)
                self.assertNotIn("TAG", record)

        out = StringIO()
        err = StringIO()
        with mock.patch.object(peer, "serve_peer", side_effect=OSError("secret path")), \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(peer.main(["--token", TOKEN_HEX]), 1)
        self.assertNotIn(TOKEN_HEX, out.getvalue() + err.getvalue())
        self.assertNotIn("secret path", err.getvalue())
        self.assertIn("socket error", err.getvalue())


class PeerEngineTest(unittest.TestCase):
    def setUp(self):
        self.lines = []
        self.replies = []
        self.clock = iter((111_000_000, 112_000_000, 113_000_000,
                           114_000_000, 115_000_000, 116_000_000))
        self.engine = peer.PeerEngine(
            TOKEN, evidence_write=self.lines.append,
            monotonic_ns=lambda: next(self.clock))

    def challenge(self, run_id=RUN_ID, sequence=SEQUENCE, nonce=NONCE):
        return peer.encode_message(
            peer.JISO_CHALLENGE, run_id, sequence, nonce, TOKEN)

    def send_reply(self, packet, address):
        self.replies.append((packet, address))

    def test_valid_challenge_binds_one_run_and_emits_sanitized_evidence(self):
        packet = self.challenge()
        self.assertTrue(self.engine.handle_datagram(
            packet, ("192.0.2.55", 50000), self.send_reply))
        reply, destination = self.replies[-1]
        self.assertEqual(destination, ("192.0.2.55", 50000))
        self.assertEqual(len(reply), len(packet))
        decoded = peer.decode_message(reply, TOKEN)
        self.assertEqual(decoded.type, peer.JISO_REPLY)
        self.assertEqual(decoded.run_id, RUN_ID)
        self.assertEqual(decoded.sequence, SEQUENCE)
        self.assertEqual(decoded.nonce, NONCE)

        record = evidence_payload(self.lines[-1])
        self.assertEqual(record, {
            "monotonic_ms": 111,
            "replied": True,
            "run": "0102030405060708",
            "sequence": SEQUENCE,
            "source_ip": "192.0.2.55",
            "source_port": 50000,
            "type": "challenge",
            "valid": True,
        })
        evidence = self.lines[-1]
        self.assertNotIn(TOKEN_HEX, evidence.upper())
        self.assertNotIn(NONCE.hex().upper(), evidence.upper())
        self.assertNotIn(reply[-16:].hex().upper(), evidence.upper())

        # A duplicate gets no second reply. A second client may participate only
        # in the already bound run; a different run never changes the binding.
        self.assertFalse(self.engine.handle_datagram(
            packet, ("192.0.2.55", 50000), self.send_reply))
        same_run = self.challenge(sequence=SEQUENCE + 1,
                                  nonce=bytes(range(0x20, 0x30)))
        self.assertTrue(self.engine.handle_datagram(
            same_run, ("192.0.2.56", 50001), self.send_reply))
        other_run = self.challenge(run_id=RUN_ID + 1, sequence=1,
                                   nonce=bytes(range(0x30, 0x40)))
        self.assertFalse(self.engine.handle_datagram(
            other_run, ("192.0.2.56", 50001), self.send_reply))
        self.assertEqual(self.engine.bound_run_id, RUN_ID)

    def test_invalid_reply_and_oversize_packets_never_reflect(self):
        challenge = bytearray(self.challenge())
        challenge[-1] ^= 0x80
        self.assertFalse(self.engine.handle_datagram(
            bytes(challenge), ("192.0.2.55", 50000), self.send_reply))
        reply_packet = peer.encode_message(
            peer.JISO_REPLY, RUN_ID, SEQUENCE, NONCE, TOKEN)
        self.assertFalse(self.engine.handle_datagram(
            reply_packet, ("192.0.2.55", 50000), self.send_reply))
        self.assertFalse(self.engine.handle_datagram(
            b"X" * 53, ("192.0.2.55", 50000), self.send_reply))

        records = [evidence_payload(line) for line in self.lines]
        self.assertEqual([item["replied"] for item in records],
                         [False, False, False])
        self.assertEqual([item["valid"] for item in records],
                         [False, True, False])
        self.assertEqual(records[0]["run"], None)
        self.assertEqual(records[0]["sequence"], None)
        self.assertEqual(records[1]["type"], "reply")
        self.assertEqual(self.replies, [])

    def test_send_failure_is_reported_without_claiming_a_reply(self):
        def fail_send(_packet, _address):
            raise OSError("injected")

        with self.assertRaises(OSError):
            self.engine.handle_datagram(
                self.challenge(), ("192.0.2.55", 50000), fail_send)
        record = evidence_payload(self.lines[-1])
        self.assertTrue(record["valid"])
        self.assertFalse(record["replied"])

    def test_short_send_is_a_failure_not_reply_evidence(self):
        def short_send(_packet, _address):
            return peer.JISO_PACKET_BYTES - 1

        with self.assertRaises(OSError):
            self.engine.handle_datagram(
                self.challenge(), ("192.0.2.55", 50000), short_send)
        record = evidence_payload(self.lines[-1])
        self.assertTrue(record["valid"])
        self.assertFalse(record["replied"])


class LoopbackIntegrationTest(unittest.TestCase):
    def test_socket_creation_failure_still_scrubs_engine_token(self):
        with mock.patch.object(peer.PeerEngine, "close", autospec=True) as close, \
                mock.patch.object(peer.socket, "socket", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                peer.serve_peer("127.0.0.1", 0, TOKEN)
        close.assert_called_once()

    def test_loopback_reply_tamper_rejection_and_clean_stop(self):
        stop_event = threading.Event()
        ready = queue.Queue()
        lines = []
        thread = threading.Thread(
            target=peer.serve_peer,
            kwargs={
                "bind": "127.0.0.1",
                "port": 0,
                "token": TOKEN,
                "evidence_write": lines.append,
                "stop_event": stop_event,
                "ready": ready,
            },
            daemon=True,
        )
        thread.start()
        port = ready.get(timeout=2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1)
        try:
            challenge = peer.encode_message(
                peer.JISO_CHALLENGE, RUN_ID, SEQUENCE, NONCE, TOKEN)
            client.sendto(challenge, ("127.0.0.1", port))
            reply, source = client.recvfrom(256)
            self.assertEqual(source, ("127.0.0.1", port))
            decoded = peer.decode_message(reply, TOKEN)
            self.assertEqual(decoded.type, peer.JISO_REPLY)
            self.assertEqual(decoded.nonce, NONCE)

            tampered = challenge[:-1] + bytes([challenge[-1] ^ 1])
            client.sendto(tampered, ("127.0.0.1", port))
            client.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                client.recvfrom(256)
        finally:
            client.close()
            stop_event.set()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(lines), 2)
        self.assertTrue(evidence_payload(lines[0])["replied"])
        self.assertFalse(evidence_payload(lines[1])["valid"])


if __name__ == "__main__":
    unittest.main()

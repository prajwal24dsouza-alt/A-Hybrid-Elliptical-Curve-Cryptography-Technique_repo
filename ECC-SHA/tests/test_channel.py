"""Unit tests for the SecureChannel class (Module 4)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from src.ecc_keygen import ECCKeyGenerator
from src.secure_channel import SecureChannel


class TestSecureChannel:

    @pytest.fixture
    def channel(self):
        return SecureChannel()

    @pytest.fixture
    def alice(self):
        keygen = ECCKeyGenerator()
        priv, pub = keygen.generate_keypair()
        return {"priv": priv, "pub": pub}

    @pytest.fixture
    def bob(self):
        keygen = ECCKeyGenerator()
        priv, pub = keygen.generate_keypair()
        return {"priv": priv, "pub": pub}

    # --- message creation ---

    def test_create_message_returns_valid_json(self, channel, alice, bob):
        msg = channel.create_secure_message(
            sender_id="alice",
            plaintext="hello",
            recipient_public_key=bob["pub"],
            sender_private_key=alice["priv"],
            sender_public_key=alice["pub"],
        )
        envelope = json.loads(msg)
        assert envelope["version"] == "1.0"
        assert envelope["sender_id"] == "alice"
        assert "timestamp" in envelope
        assert "signature" in envelope
        assert "encrypted_message" in envelope

    # --- round-trip ---

    def test_send_receive_roundtrip(self, channel, alice, bob):
        msg_text = "Hello Bob! This is a secret from Alice."
        msg = channel.create_secure_message(
            sender_id="alice",
            plaintext=msg_text,
            recipient_public_key=bob["pub"],
            sender_private_key=alice["priv"],
            sender_public_key=alice["pub"],
        )
        result = channel.receive_secure_message(msg, bob["priv"], alice["pub"])
        assert result["plaintext"] == msg_text
        assert result["verified"] is True
        assert result["integrity_ok"] is True

    # --- bidirectional ---

    def test_bidirectional_communication(self, channel, alice, bob):
        # Alice → Bob
        msg1 = channel.create_secure_message(
            "alice", "Hello Bob!", bob["pub"], alice["priv"], alice["pub"]
        )
        r1 = channel.receive_secure_message(msg1, bob["priv"], alice["pub"])
        assert r1["plaintext"] == "Hello Bob!"

        # Bob → Alice
        msg2 = channel.create_secure_message(
            "bob", "Hi Alice!", alice["pub"], bob["priv"], bob["pub"]
        )
        r2 = channel.receive_secure_message(msg2, alice["priv"], bob["pub"])
        assert r2["plaintext"] == "Hi Alice!"

    # --- tampering ---

    def test_tampering_detected(self, channel, alice, bob):
        msg = channel.create_secure_message(
            "alice", "Original message", bob["pub"], alice["priv"], alice["pub"]
        )
        # Tamper with the actual ciphertext bytes (flip a byte in the base64)
        import base64
        envelope = json.loads(msg)
        ct_bytes = base64.b64decode(envelope["encrypted_message"]["ciphertext"])
        tampered_bytes = bytearray(ct_bytes)
        tampered_bytes[0] ^= 0xFF
        envelope["encrypted_message"]["ciphertext"] = base64.b64encode(
            bytes(tampered_bytes)
        ).decode("ascii")
        tampered = json.dumps(envelope)

        result = channel.receive_secure_message(tampered, bob["priv"], alice["pub"])
        tamper_detected = (
            result["plaintext"] is None
            or not result["verified"]
            or not result["integrity_ok"]
        )
        assert tamper_detected

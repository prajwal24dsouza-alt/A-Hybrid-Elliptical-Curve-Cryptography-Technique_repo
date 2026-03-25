"""Integration tests — end-to-end secure communication workflows."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cryptography.hazmat.primitives import serialization

from src.ecc_keygen import ECCKeyGenerator
from src.hybrid_encryption import HybridEncryption
from src.digital_signature import DigitalSignature
from src.secure_channel import SecureChannel


class TestIntegration:

    @pytest.fixture
    def setup(self):
        keygen = ECCKeyGenerator()
        hybrid = HybridEncryption()
        sig = DigitalSignature()
        channel = SecureChannel(hybrid, sig)

        alice_priv, alice_pub = keygen.generate_keypair()
        bob_priv, bob_pub = keygen.generate_keypair()

        return {
            "keygen": keygen,
            "hybrid": hybrid,
            "sig": sig,
            "channel": channel,
            "alice_priv": alice_priv,
            "alice_pub": alice_pub,
            "bob_priv": bob_priv,
            "bob_pub": bob_pub,
        }

    def test_end_to_end_communication(self, setup):
        """Full cycle: Alice sends, Bob receives, Bob replies, Alice receives."""
        channel = setup["channel"]

        # Alice → Bob
        msg = channel.create_secure_message(
            "alice", "Secret data",
            setup["bob_pub"], setup["alice_priv"], setup["alice_pub"],
        )
        r = channel.receive_secure_message(msg, setup["bob_priv"], setup["alice_pub"])
        assert r["plaintext"] == "Secret data"
        assert r["verified"]
        assert r["integrity_ok"]

        # Bob → Alice
        reply = channel.create_secure_message(
            "bob", "Acknowledged",
            setup["alice_pub"], setup["bob_priv"], setup["bob_pub"],
        )
        r2 = channel.receive_secure_message(reply, setup["alice_priv"], setup["bob_pub"])
        assert r2["plaintext"] == "Acknowledged"
        assert r2["verified"]

    def test_multiple_messages(self, setup):
        """Send several messages in a session."""
        channel = setup["channel"]
        messages = [
            "Message 1: Hello",
            "Message 2: How are you?",
            "Message 3: Fine, thanks!",
            "Message 4: 🔐 encrypted emoji test",
            "Message 5: " + "x" * 5000,  # large payload
        ]
        for text in messages:
            msg = channel.create_secure_message(
                "alice", text,
                setup["bob_pub"], setup["alice_priv"], setup["alice_pub"],
            )
            r = channel.receive_secure_message(msg, setup["bob_priv"], setup["alice_pub"])
            assert r["plaintext"] == text
            assert r["verified"]

    def test_keygen_save_load_then_communicate(self, setup, tmp_path):
        """Generate keys, save to disk, reload, then use for communication."""
        keygen = setup["keygen"]
        channel = setup["channel"]

        # Generate and save
        priv, pub = keygen.generate_keypair()
        keygen.save_keypair(priv, pub, str(tmp_path / "keys"), "charlie")

        # Reload
        priv2, pub2 = keygen.load_keypair(str(tmp_path / "keys"), "charlie")

        # Communicate using reloaded keys
        msg = channel.create_secure_message(
            "charlie", "Loaded from disk!",
            setup["bob_pub"], priv2, pub2,
        )
        r = channel.receive_secure_message(msg, setup["bob_priv"], pub2)
        assert r["plaintext"] == "Loaded from disk!"
        assert r["verified"]

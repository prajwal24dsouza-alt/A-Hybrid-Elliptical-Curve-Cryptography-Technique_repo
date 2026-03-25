"""Unit tests for the DigitalSignature class (Module 3)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from src.digital_signature import DigitalSignature


class TestDigitalSignature:

    @pytest.fixture
    def sig_handler(self):
        return DigitalSignature()

    @pytest.fixture
    def keypair(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        return priv, pub

    # --- signing ---

    def test_sign_returns_hex_string(self, sig_handler, keypair):
        priv, _ = keypair
        signature = sig_handler.sign_message("test", priv)
        assert isinstance(signature, str)
        # DER-encoded ECDSA signature → ~140 hex chars
        assert len(signature) >= 100

    def test_sign_produces_different_signatures(self, sig_handler, keypair):
        priv, _ = keypair
        s1 = sig_handler.sign_message("test", priv)
        s2 = sig_handler.sign_message("test", priv)
        # ECDSA uses randomised nonces → different sigs for same message
        assert s1 != s2

    # --- verification ---

    def test_verify_valid_signature(self, sig_handler, keypair):
        priv, pub = keypair
        sig = sig_handler.sign_message("important message", priv)
        assert sig_handler.verify_signature("important message", sig, pub) is True

    def test_verify_wrong_message(self, sig_handler, keypair):
        priv, pub = keypair
        sig = sig_handler.sign_message("original", priv)
        assert sig_handler.verify_signature("tampered", sig, pub) is False

    def test_verify_wrong_key(self, sig_handler, keypair):
        priv, _ = keypair
        wrong_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
        sig = sig_handler.sign_message("test", priv)
        assert sig_handler.verify_signature("test", sig, wrong_pub) is False

    # --- hashing ---

    def test_hash_length(self, sig_handler):
        h = sig_handler.get_message_hash("hello")
        assert len(h) == 64  # SHA-256 → 64 hex chars

    def test_hash_consistency(self, sig_handler):
        h1 = sig_handler.get_message_hash("hello world")
        h2 = sig_handler.get_message_hash("hello world")
        assert h1 == h2

    def test_hash_uniqueness(self, sig_handler):
        h1 = sig_handler.get_message_hash("message A")
        h2 = sig_handler.get_message_hash("message B")
        assert h1 != h2

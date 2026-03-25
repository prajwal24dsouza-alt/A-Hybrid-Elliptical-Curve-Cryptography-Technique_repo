"""Unit tests for the HybridEncryption class (Module 2)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from src.hybrid_encryption import HybridEncryption


class TestHybridEncryption:

    @pytest.fixture
    def hybrid(self):
        return HybridEncryption()

    @pytest.fixture
    def keypair(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        return priv, pub

    # --- ECDH ---

    def test_ecdh_produces_shared_secret(self, hybrid):
        alice_priv = ec.generate_private_key(ec.SECP256R1())
        bob_priv = ec.generate_private_key(ec.SECP256R1())
        shared = hybrid._perform_ecdh(alice_priv, bob_priv.public_key())
        assert len(shared) >= 32

    def test_ecdh_shared_secret_matches(self, hybrid):
        alice_priv = ec.generate_private_key(ec.SECP256R1())
        bob_priv = ec.generate_private_key(ec.SECP256R1())
        s1 = hybrid._perform_ecdh(alice_priv, bob_priv.public_key())
        s2 = hybrid._perform_ecdh(bob_priv, alice_priv.public_key())
        assert s1 == s2

    # --- HKDF ---

    def test_hkdf_key_length(self, hybrid):
        shared = os.urandom(32)
        key = hybrid._derive_encryption_key(shared)
        assert len(key) == 32

    def test_hkdf_deterministic(self, hybrid):
        shared = os.urandom(32)
        k1 = hybrid._derive_encryption_key(shared)
        k2 = hybrid._derive_encryption_key(shared)
        # HKDF without salt is deterministic for same input
        # (note: salt=None defaults to zeros, so yes deterministic)
        assert k1 == k2

    def test_hkdf_different_inputs(self, hybrid):
        k1 = hybrid._derive_encryption_key(os.urandom(32))
        k2 = hybrid._derive_encryption_key(os.urandom(32))
        assert k1 != k2

    # --- AES-GCM ---

    def test_aes_gcm_roundtrip(self, hybrid):
        key = os.urandom(32)
        data = b"Hello, AES-GCM!"
        enc = hybrid._encrypt_aes_gcm(data, key)
        dec = hybrid._decrypt_aes_gcm(enc["ciphertext"], key, enc["iv"], enc["tag"])
        assert dec == data

    def test_aes_gcm_tampering_detection(self, hybrid):
        key = os.urandom(32)
        data = b"Sensitive data"
        enc = hybrid._encrypt_aes_gcm(data, key)

        tampered = bytearray(enc["ciphertext"])
        tampered[0] ^= 0xFF
        result = hybrid._decrypt_aes_gcm(bytes(tampered), key, enc["iv"], enc["tag"])
        assert result is None

    # --- Full ECIES ---

    def test_ecies_roundtrip(self, hybrid, keypair):
        priv, pub = keypair
        message = "Secret message for ECIES test"
        bundle = hybrid.encrypt_message(message, pub)
        decrypted = hybrid.decrypt_message(bundle, priv)
        assert decrypted == message

    def test_ecies_with_unicode(self, hybrid, keypair):
        priv, pub = keypair
        message = "Unicode test: こんにちは 🔐 Ελληνικά"
        bundle = hybrid.encrypt_message(message, pub)
        decrypted = hybrid.decrypt_message(bundle, priv)
        assert decrypted == message

    def test_ecies_wrong_key_fails(self, hybrid, keypair):
        _, pub = keypair
        wrong_priv = ec.generate_private_key(ec.SECP256R1())
        bundle = hybrid.encrypt_message("test", pub)
        result = hybrid.decrypt_message(bundle, wrong_priv)
        assert result is None

    def test_ecies_large_message(self, hybrid, keypair):
        priv, pub = keypair
        message = "A" * 10000
        bundle = hybrid.encrypt_message(message, pub)
        decrypted = hybrid.decrypt_message(bundle, priv)
        assert decrypted == message

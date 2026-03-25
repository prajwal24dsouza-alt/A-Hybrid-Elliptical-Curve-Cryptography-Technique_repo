"""Unit tests for the ECCKeyGenerator class (Module 1)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec

from src.ecc_keygen import ECCKeyGenerator


class TestECCKeyGenerator:

    @pytest.fixture
    def keygen(self):
        return ECCKeyGenerator()

    @pytest.fixture
    def keypair(self, keygen):
        return keygen.generate_keypair()

    # --- generation ---

    def test_generate_keypair_returns_two_keys(self, keygen):
        priv, pub = keygen.generate_keypair()
        assert priv is not None
        assert pub is not None

    def test_generate_keypair_types(self, keygen):
        priv, pub = keygen.generate_keypair()
        assert hasattr(priv, "sign")
        assert hasattr(pub, "verify")

    def test_different_keypairs_are_unique(self, keygen):
        _, pub1 = keygen.generate_keypair()
        _, pub2 = keygen.generate_keypair()
        fp1 = keygen.get_key_fingerprint(pub1)
        fp2 = keygen.get_key_fingerprint(pub2)
        assert fp1 != fp2

    # --- PEM export / import ---

    def test_export_private_key_pem_format(self, keygen, keypair):
        priv, _ = keypair
        pem = keygen.export_private_key(priv)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_export_public_key_pem_format(self, keygen, keypair):
        _, pub = keypair
        pem = keygen.export_public_key(pub)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_export_import_roundtrip(self, keygen, keypair):
        priv, pub = keypair
        priv_pem = keygen.export_private_key(priv)
        pub_pem = keygen.export_public_key(pub)

        priv_loaded = keygen.import_private_key(priv_pem)
        pub_loaded = keygen.import_public_key(pub_pem)

        fp_original = keygen.get_key_fingerprint(pub)
        fp_loaded = keygen.get_key_fingerprint(pub_loaded)
        assert fp_original == fp_loaded

    # --- file I/O ---

    def test_save_load_keypair(self, keygen, keypair, tmp_path):
        priv, pub = keypair
        key_dir = str(tmp_path / "test_keys")
        keygen.save_keypair(priv, pub, key_dir, "test_user")

        assert (Path(key_dir) / "test_user_private.pem").exists()
        assert (Path(key_dir) / "test_user_public.pem").exists()

        priv_loaded, pub_loaded = keygen.load_keypair(key_dir, "test_user")
        fp_original = keygen.get_key_fingerprint(pub)
        fp_loaded = keygen.get_key_fingerprint(pub_loaded)
        assert fp_original == fp_loaded

    # --- fingerprinting ---

    def test_fingerprint_length(self, keygen, keypair):
        _, pub = keypair
        fp = keygen.get_key_fingerprint(pub)
        assert len(fp) == 16  # 8 bytes → 16 hex chars

    def test_fingerprint_consistency(self, keygen, keypair):
        _, pub = keypair
        fp1 = keygen.get_key_fingerprint(pub)
        fp2 = keygen.get_key_fingerprint(pub)
        assert fp1 == fp2

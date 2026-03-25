"""Performance benchmark tests."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from src.ecc_keygen import ECCKeyGenerator
from src.hybrid_encryption import HybridEncryption
from src.digital_signature import DigitalSignature


class TestPerformance:

    def test_key_generation_speed(self):
        """10 key-pair generations should complete in < 2 seconds."""
        keygen = ECCKeyGenerator()
        start = time.perf_counter()
        for _ in range(10):
            keygen.generate_keypair()
        elapsed = time.perf_counter() - start
        print(f"\n  Key generation: {elapsed*1000:.1f} ms for 10 pairs "
              f"({elapsed/10*1000:.1f} ms / pair)")
        assert elapsed < 2.0

    def test_encryption_speed(self):
        """100 encryptions should complete in < 10 seconds."""
        hybrid = HybridEncryption()
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()

        start = time.perf_counter()
        for _ in range(100):
            hybrid.encrypt_message("Test message for benchmark", pub)
        elapsed = time.perf_counter() - start
        print(f"\n  Encryption: {elapsed*1000:.1f} ms for 100 msgs "
              f"({elapsed/100*1000:.1f} ms / msg)")
        assert elapsed < 10.0

    def test_signature_speed(self):
        """100 sign + verify cycles should complete in < 10 seconds."""
        sig = DigitalSignature()
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()

        start = time.perf_counter()
        for _ in range(100):
            s = sig.sign_message("Benchmark message", priv)
            sig.verify_signature("Benchmark message", s, pub)
        elapsed = time.perf_counter() - start
        print(f"\n  Sign+Verify: {elapsed*1000:.1f} ms for 100 cycles "
              f"({elapsed/100*1000:.1f} ms / cycle)")
        assert elapsed < 10.0

"""
Hybrid ECC Secure Communication Package
========================================
Production-ready Elliptic Curve Cryptography implementation.

Modules:
    - ecc_keygen: ECC key pair generation, export/import, storage
    - hybrid_encryption: ECIES encryption (ECDH + HKDF + AES-256-GCM)
    - digital_signature: ECDSA digital signing and verification
    - secure_channel: Secure communication protocol combining encryption + signatures
"""

from .ecc_keygen import ECCKeyGenerator
from .hybrid_encryption import HybridEncryption
from .digital_signature import DigitalSignature
from .secure_channel import SecureChannel

__all__ = [
    "ECCKeyGenerator",
    "HybridEncryption",
    "DigitalSignature",
    "SecureChannel",
]

__version__ = "1.0.0"

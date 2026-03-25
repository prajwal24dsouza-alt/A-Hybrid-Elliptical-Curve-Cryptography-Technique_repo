"""
Digital Signature Module
========================
Provides the ``DigitalSignature`` class for ECDSA signing and verification,
plus SHA-256 message hashing.

Example::

    sig = DigitalSignature()
    priv = ec.generate_private_key(ec.SECP256R1())
    pub  = priv.public_key()

    signature = sig.sign_message("Important message", priv)
    is_valid  = sig.verify_signature("Important message", signature, pub)
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import hashlib


class DigitalSignature:
    """ECDSA Digital Signature implementation.

    Args:
        hash_algorithm: A ``cryptography`` hash instance. Defaults to SHA-256.
    """

    def __init__(self, hash_algorithm=None):
        self.hash_algo = hash_algorithm or hashes.SHA256()
        self.backend = default_backend()

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------
    def sign_message(self, message, private_key):
        """Sign a message with ECDSA.

        Args:
            message (str | bytes): Data to sign.
            private_key: ECC private key object.

        Returns:
            str: DER-encoded signature as a hex string.

        Example::

            >>> sig = DigitalSignature()
            >>> signature = sig.sign_message("hello", private_key)
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        signature = private_key.sign(message, ec.ECDSA(self.hash_algo))
        return signature.hex()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify_signature(self, message, signature_hex, public_key):
        """Verify an ECDSA signature.

        Args:
            message (str | bytes): Original message.
            signature_hex (str): DER-encoded signature as hex.
            public_key: ECC public key object.

        Returns:
            bool: ``True`` if the signature is valid, ``False`` otherwise.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                message,
                ec.ECDSA(self.hash_algo),
            )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Message hashing
    # ------------------------------------------------------------------
    def get_message_hash(self, message):
        """Compute the SHA-256 hash of a message.

        Args:
            message (str | bytes): Data to hash.

        Returns:
            str: 64-character hexadecimal digest.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hashlib.sha256(message).hexdigest()


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    from src.utils import print_header, print_step, print_result, truncate_hex

    print_header("Digital Signatures (ECDSA) — Module 3 Demo")

    sig = DigitalSignature()

    print_step(1, "Generating keypair…")
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    print_result("Keypair", "Generated")

    message = "A HYBRID ELLIPTIC CURVE CRYPTOGRAPHY TECHNIQUE FOR SECURED COMMUNICATION"

    print_step(2, "Signing message…")
    signature = sig.sign_message(message, priv)
    print_result("Signature", truncate_hex(signature))
    print_result("Length", f"{len(signature)} hex chars")

    print_step(3, "Verifying with correct key…")
    valid = sig.verify_signature(message, signature, pub)
    print_result("Valid signature", valid)

    print_step(4, "Verifying with wrong message…")
    invalid = sig.verify_signature("tampered message", signature, pub)
    print_result("Invalid message rejected", not invalid)

    print_step(5, "Verifying with wrong key…")
    wrong_priv = ec.generate_private_key(ec.SECP256R1())
    wrong_pub = wrong_priv.public_key()
    invalid2 = sig.verify_signature(message, signature, wrong_pub)
    print_result("Wrong key rejected", not invalid2)

    print_step(6, "Message hashing…")
    h1 = sig.get_message_hash(message)
    h2 = sig.get_message_hash(message)
    print_result("Hash", truncate_hex(h1))
    print_result("Consistent", h1 == h2)
    print_result("Length", f"{len(h1)} hex chars")

    print("\n✅  Module 3 — Complete!\n")

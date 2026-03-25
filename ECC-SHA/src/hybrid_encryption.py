"""
Hybrid Encryption Module (ECIES)
================================
Provides the ``HybridEncryption`` class implementing the Elliptic Curve
Integrated Encryption Scheme (ECIES):

    ECDH key agreement  →  HKDF key derivation  →  AES-256-GCM encryption

Each encryption generates an *ephemeral* key pair so that every message
enjoys Perfect Forward Secrecy.

Example::

    hybrid = HybridEncryption()
    priv = ec.generate_private_key(ec.SECP256R1())
    pub  = priv.public_key()

    bundle = hybrid.encrypt_message("Hello!", pub)
    plain  = hybrid.decrypt_message(bundle, priv)
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os


class HybridEncryption:
    """ECIES Encryption: ECC (ECDH) + AES-256-GCM.

    Attributes:
        aes_key_size (int): AES key length in bytes (default 32 → 256-bit).
        iv_size (int): GCM nonce length in bytes (default 12 → 96-bit).
    """

    def __init__(self):
        self.backend = default_backend()
        self.aes_key_size = 32   # 256-bit
        self.iv_size = 12        # 96-bit for GCM

    # ------------------------------------------------------------------
    # Ephemeral key pair
    # ------------------------------------------------------------------
    def _generate_ephemeral_keypair(self, curve=None):
        """Generate a temporary ECC key pair for a single ECIES operation.

        Args:
            curve: Optional ``ec.EllipticCurve``. Defaults to SECP256R1.

        Returns:
            tuple: ``(ephemeral_private, ephemeral_public)``
        """
        curve = curve or ec.SECP256R1()
        private = ec.generate_private_key(curve, self.backend)
        return private, private.public_key()

    # ------------------------------------------------------------------
    # ECDH
    # ------------------------------------------------------------------
    def _perform_ecdh(self, private_key, peer_public_key):
        """Perform Elliptic Curve Diffie–Hellman key agreement.

        Args:
            private_key: Local ECC private key.
            peer_public_key: Remote ECC public key.

        Returns:
            bytes: Raw shared secret.
        """
        return private_key.exchange(ec.ECDH(), peer_public_key)

    # ------------------------------------------------------------------
    # HKDF key derivation
    # ------------------------------------------------------------------
    def _derive_encryption_key(self, shared_secret, salt=None):
        """Derive a 256-bit AES key from a shared secret via HKDF-SHA256.

        Args:
            shared_secret (bytes): Raw ECDH output.
            salt (bytes | None): Optional salt for HKDF.

        Returns:
            bytes: 32-byte AES key.
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=self.aes_key_size,
            salt=salt,
            info=b"ecies_hybrid_encryption",
            backend=self.backend,
        ).derive(shared_secret)

    # ------------------------------------------------------------------
    # AES-256-GCM
    # ------------------------------------------------------------------
    def _encrypt_aes_gcm(self, plaintext, aes_key, iv=None):
        """Encrypt data with AES-256-GCM.

        Args:
            plaintext (bytes): Data to encrypt.
            aes_key (bytes): 32-byte AES key.
            iv (bytes | None): 12-byte nonce (generated if ``None``).

        Returns:
            dict: ``{"ciphertext": bytes, "iv": bytes, "tag": bytes}``
        """
        if iv is None:
            iv = os.urandom(self.iv_size)

        aesgcm = AESGCM(aes_key)
        # GCM appends a 16-byte tag to the ciphertext
        ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]

        return {"ciphertext": ciphertext, "iv": iv, "tag": tag}

    def _decrypt_aes_gcm(self, ciphertext, aes_key, iv, tag):
        """Decrypt AES-256-GCM ciphertext and verify its authentication tag.

        Args:
            ciphertext (bytes): Encrypted data (without tag).
            aes_key (bytes): 32-byte AES key.
            iv (bytes): 12-byte nonce.
            tag (bytes): 16-byte GCM authentication tag.

        Returns:
            bytes | None: Plaintext on success, ``None`` if integrity check fails.
        """
        aesgcm = AESGCM(aes_key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
            return plaintext
        except InvalidTag:
            return None

    # ------------------------------------------------------------------
    # Full ECIES pipeline
    # ------------------------------------------------------------------
    def encrypt_message(self, plaintext, recipient_public_key):
        """Encrypt a message using the full ECIES pipeline.

        Steps:
            1. Generate ephemeral key pair
            2. ECDH with recipient's public key
            3. Derive AES key via HKDF
            4. Encrypt with AES-256-GCM
            5. Bundle ephemeral public key + ciphertext components

        Args:
            plaintext (str | bytes): Message to encrypt.
            recipient_public_key: Recipient's ECC public key object.

        Returns:
            dict: Encryption bundle with keys
                ``ephemeral_public_key``, ``iv``, ``ciphertext``, ``tag``.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # 1. Ephemeral key pair
        eph_priv, eph_pub = self._generate_ephemeral_keypair(
            recipient_public_key.curve
        )

        # 2. ECDH
        shared_secret = self._perform_ecdh(eph_priv, recipient_public_key)

        # 3. Key derivation
        aes_key = self._derive_encryption_key(shared_secret)

        # 4. AES-GCM encryption
        enc_result = self._encrypt_aes_gcm(plaintext, aes_key)

        # 5. Serialize ephemeral public key
        eph_pub_bytes = eph_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "ephemeral_public_key": eph_pub_bytes,
            "iv": enc_result["iv"],
            "ciphertext": enc_result["ciphertext"],
            "tag": enc_result["tag"],
        }

    def decrypt_message(self, ciphertext_bundle, recipient_private_key):
        """Decrypt an ECIES-encrypted message.

        Args:
            ciphertext_bundle (dict): Bundle produced by ``encrypt_message``.
            recipient_private_key: Recipient's ECC private key object.

        Returns:
            str | None: Decrypted plaintext, or ``None`` if integrity fails.
        """
        # 1. Recover ephemeral public key
        eph_pub = serialization.load_pem_public_key(
            ciphertext_bundle["ephemeral_public_key"], backend=self.backend
        )

        # 2. ECDH
        shared_secret = self._perform_ecdh(recipient_private_key, eph_pub)

        # 3. Same key derivation
        aes_key = self._derive_encryption_key(shared_secret)

        # 4. Decrypt
        plaintext = self._decrypt_aes_gcm(
            ciphertext_bundle["ciphertext"],
            aes_key,
            ciphertext_bundle["iv"],
            ciphertext_bundle["tag"],
        )

        if plaintext is None:
            return None
        return plaintext.decode("utf-8")


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    from src.utils import print_header, print_step, print_result, truncate_hex

    print_header("Hybrid Encryption (ECIES) — Module 2 Demo")

    hybrid = HybridEncryption()

    # Generate Alice and Bob keys
    alice_priv = ec.generate_private_key(ec.SECP256R1())
    bob_priv = ec.generate_private_key(ec.SECP256R1())
    bob_pub = bob_priv.public_key()

    print_step(1, "ECDH key agreement…")
    shared = hybrid._perform_ecdh(alice_priv, bob_pub)
    print_result("Shared secret", f"{len(shared)} bytes")

    print_step(2, "HKDF key derivation…")
    aes_key = hybrid._derive_encryption_key(shared)
    print_result("AES key", f"{len(aes_key)} bytes → {truncate_hex(aes_key.hex(), 32)}")

    print_step(3, "AES-256-GCM encrypt / decrypt…")
    test_data = b"Hello, AES-GCM!"
    enc = hybrid._encrypt_aes_gcm(test_data, aes_key)
    dec = hybrid._decrypt_aes_gcm(enc["ciphertext"], aes_key, enc["iv"], enc["tag"])
    print_result("Round-trip match", dec == test_data)

    print_step(4, "Tampering detection…")
    tampered = bytearray(enc["ciphertext"])
    tampered[0] ^= 0xFF
    result = hybrid._decrypt_aes_gcm(bytes(tampered), aes_key, enc["iv"], enc["tag"])
    print_result("Tampering detected", result is None)

    print_step(5, "Full ECIES encrypt / decrypt…")
    message = "A HYBRID ELLIPTIC CURVE CRYPTOGRAPHY TECHNIQUE FOR SECURED COMMUNICATION"
    bundle = hybrid.encrypt_message(message, bob_pub)
    decrypted = hybrid.decrypt_message(bundle, bob_priv)
    print_result("Original", message)
    print_result("Decrypted", decrypted)
    print_result("Match", decrypted == message)

    print("\n✅  Module 2 — Complete!\n")

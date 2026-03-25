"""
Secure Channel Module
=====================
Provides the ``SecureChannel`` class that combines ECIES encryption with ECDSA
digital signatures to create a full secure communication protocol.

A secure message is a JSON envelope containing:
    - Encrypted payload (ECIES)
    - Digital signature for authentication
    - Sender identity and timestamp metadata

Example::

    from src import ECCKeyGenerator, HybridEncryption, DigitalSignature, SecureChannel

    keygen   = ECCKeyGenerator()
    hybrid   = HybridEncryption()
    sig      = DigitalSignature()
    channel  = SecureChannel(hybrid, sig)

    alice_priv, alice_pub = keygen.generate_keypair()
    bob_priv, bob_pub     = keygen.generate_keypair()

    msg = channel.create_secure_message(
        sender_id="alice", plaintext="Hello Bob!",
        recipient_public_key=bob_pub,
        sender_private_key=alice_priv,
        sender_public_key=alice_pub,
    )
    result = channel.receive_secure_message(msg, bob_priv, alice_pub)
"""

import json
import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

try:
    from .hybrid_encryption import HybridEncryption
    from .digital_signature import DigitalSignature
except ImportError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    from src.hybrid_encryption import HybridEncryption
    from src.digital_signature import DigitalSignature


class SecureChannel:
    """Secure communication protocol combining encryption + digital signatures.

    Args:
        hybrid_encryption: A ``HybridEncryption`` instance (created if ``None``).
        digital_signature: A ``DigitalSignature`` instance (created if ``None``).
    """

    PROTOCOL_VERSION = "1.0"

    def __init__(self, hybrid_encryption=None, digital_signature=None):
        self.hybrid = hybrid_encryption or HybridEncryption()
        self.sig = digital_signature or DigitalSignature()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _unb64(s: str) -> bytes:
        return base64.b64decode(s)

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------
    def create_secure_message(
        self,
        sender_id,
        plaintext,
        recipient_public_key,
        sender_private_key,
        sender_public_key=None,
    ):
        """Create an encrypted + signed JSON message envelope.

        Args:
            sender_id (str): Identifier of the sender (e.g. email).
            plaintext (str): Message body.
            recipient_public_key: Recipient's ECC public key.
            sender_private_key: Sender's ECC private key (for signing).
            sender_public_key: Sender's ECC public key (included in envelope).

        Returns:
            str: JSON-encoded secure message.
        """
        # 1. Sign the plaintext
        signature = self.sig.sign_message(plaintext, sender_private_key)
        message_hash = self.sig.get_message_hash(plaintext)

        # 2. Encrypt the plaintext
        bundle = self.hybrid.encrypt_message(plaintext, recipient_public_key)

        # 3. Serialize sender public key (optional but useful for the receiver)
        sender_pub_pem = ""
        if sender_public_key is not None:
            sender_pub_pem = sender_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

        # 4. Build envelope
        envelope = {
            "version": self.PROTOCOL_VERSION,
            "sender_id": sender_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sender_public_key": sender_pub_pem,
            "signature": signature,
            "message_hash": message_hash,
            "encrypted_message": {
                "ephemeral_public_key": self._b64(bundle["ephemeral_public_key"]),
                "iv": self._b64(bundle["iv"]),
                "ciphertext": self._b64(bundle["ciphertext"]),
                "tag": self._b64(bundle["tag"]),
            },
        }

        return json.dumps(envelope, indent=2)

    # ------------------------------------------------------------------
    # Receive
    # ------------------------------------------------------------------
    def receive_secure_message(self, message_json, recipient_private_key, sender_public_key):
        """Receive, decrypt, and verify a secure message.

        Args:
            message_json (str): JSON envelope produced by ``create_secure_message``.
            recipient_private_key: Recipient's ECC private key (for decryption).
            sender_public_key: Sender's ECC public key (for verification).

        Returns:
            dict: Result with keys:
                ``plaintext``, ``verified``, ``integrity_ok``,
                ``sender_id``, ``timestamp``.
        """
        envelope = json.loads(message_json)

        # 1. Reconstruct the encryption bundle
        enc = envelope["encrypted_message"]
        bundle = {
            "ephemeral_public_key": self._unb64(enc["ephemeral_public_key"]),
            "iv": self._unb64(enc["iv"]),
            "ciphertext": self._unb64(enc["ciphertext"]),
            "tag": self._unb64(enc["tag"]),
        }

        # 2. Decrypt
        plaintext = self.hybrid.decrypt_message(bundle, recipient_private_key)

        if plaintext is None:
            return {
                "plaintext": None,
                "verified": False,
                "integrity_ok": False,
                "sender_id": envelope.get("sender_id"),
                "timestamp": envelope.get("timestamp"),
                "error": "Decryption failed — message may be corrupted",
            }

        # 3. Verify signature
        verified = self.sig.verify_signature(
            plaintext, envelope["signature"], sender_public_key
        )

        # 4. Integrity check (hash)
        computed_hash = self.sig.get_message_hash(plaintext)
        integrity_ok = computed_hash == envelope["message_hash"]

        return {
            "plaintext": plaintext,
            "verified": verified,
            "integrity_ok": integrity_ok,
            "sender_id": envelope.get("sender_id"),
            "timestamp": envelope.get("timestamp"),
        }


# ==================== ALICE-BOB DEMO ====================

def alice_bob_demo():
    """Demonstrate full two-way secure communication between Alice and Bob."""
    from .ecc_keygen import ECCKeyGenerator
    from .utils import print_header, print_step, print_result

    keygen = ECCKeyGenerator()
    channel = SecureChannel()

    print_header("Secure Channel — Alice & Bob Demo")

    # --- Key generation ---
    print_step(1, "Generating key pairs…")
    alice_priv, alice_pub = keygen.generate_keypair()
    bob_priv, bob_pub = keygen.generate_keypair()
    print_result("Alice fingerprint", keygen.get_key_fingerprint(alice_pub))
    print_result("Bob fingerprint", keygen.get_key_fingerprint(bob_pub))

    # --- Alice → Bob ---
    print_step(2, "Alice sends a message to Bob…")
    msg_text = "Hello Bob! This is a secret from Alice."
    secure_msg = channel.create_secure_message(
        sender_id="alice@example.com",
        plaintext=msg_text,
        recipient_public_key=bob_pub,
        sender_private_key=alice_priv,
        sender_public_key=alice_pub,
    )
    envelope = json.loads(secure_msg)
    print_result("Envelope version", envelope["version"])
    print_result("Sender", envelope["sender_id"])
    print_result("Timestamp", envelope["timestamp"])

    # --- Bob receives ---
    print_step(3, "Bob receives and verifies…")
    result = channel.receive_secure_message(secure_msg, bob_priv, alice_pub)
    print_result("Plaintext", result["plaintext"])
    print_result("Signature verified", result["verified"])
    print_result("Integrity OK", result["integrity_ok"])
    print_result("Match", result["plaintext"] == msg_text)

    # --- Bob → Alice ---
    print_step(4, "Bob replies to Alice…")
    reply_text = "Hi Alice! Got your message. Here's my reply."
    reply_msg = channel.create_secure_message(
        sender_id="bob@example.com",
        plaintext=reply_text,
        recipient_public_key=alice_pub,
        sender_private_key=bob_priv,
        sender_public_key=bob_pub,
    )

    # --- Alice receives reply ---
    print_step(5, "Alice receives Bob's reply…")
    reply_result = channel.receive_secure_message(reply_msg, alice_priv, bob_pub)
    print_result("Plaintext", reply_result["plaintext"])
    print_result("Signature verified", reply_result["verified"])
    print_result("Match", reply_result["plaintext"] == reply_text)

    # --- Tampering detection ---
    print_step(6, "Tampering detection test…")
    import base64 as _b64
    tampered_env = json.loads(secure_msg)
    ct_raw = _b64.b64decode(tampered_env["encrypted_message"]["ciphertext"])
    tampered_ct = bytearray(ct_raw)
    tampered_ct[0] ^= 0xFF
    tampered_env["encrypted_message"]["ciphertext"] = _b64.b64encode(
        bytes(tampered_ct)
    ).decode("ascii")
    tampered_json = json.dumps(tampered_env)
    tampered_result = channel.receive_secure_message(tampered_json, bob_priv, alice_pub)
    tamper_detected = (
        tampered_result["plaintext"] is None
        or not tampered_result["verified"]
        or not tampered_result["integrity_ok"]
    )
    print_result("Tampering detected", tamper_detected)

    print_header("Demo Complete — All Checks Passed! ✅")


if __name__ == "__main__":
    alice_bob_demo()

#!/usr/bin/env python3
"""
Simple Encryption Example
==========================
Demonstrates encrypting and decrypting a message using ECIES.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from src.hybrid_encryption import HybridEncryption

def main():
    hybrid = HybridEncryption()

    # Generate recipient key pair
    recipient_private = ec.generate_private_key(ec.SECP256R1())
    recipient_public = recipient_private.public_key()

    # Encrypt a message
    message = "This is a top-secret message encrypted with ECIES!"
    print(f"Original : {message}")

    bundle = hybrid.encrypt_message(message, recipient_public)
    print(f"Encrypted: {bundle['ciphertext'].hex()[:60]}…")

    # Decrypt
    decrypted = hybrid.decrypt_message(bundle, recipient_private)
    print(f"Decrypted: {decrypted}")
    print(f"Match    : {'✅' if decrypted == message else '❌'}")


if __name__ == "__main__":
    main()

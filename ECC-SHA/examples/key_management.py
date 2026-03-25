#!/usr/bin/env python3
"""
Key Management Example
======================
Demonstrates generating, saving, loading, and fingerprinting ECC keys.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ecc_keygen import ECCKeyGenerator

def main():
    keygen = ECCKeyGenerator()

    # Generate
    print("Generating key pairs for Alice and Bob…")
    alice_priv, alice_pub = keygen.generate_keypair()
    bob_priv, bob_pub = keygen.generate_keypair()

    # Fingerprints
    print(f"Alice fingerprint: {keygen.get_key_fingerprint(alice_pub)}")
    print(f"Bob   fingerprint: {keygen.get_key_fingerprint(bob_pub)}")

    # Save
    keygen.save_keypair(alice_priv, alice_pub, "keys", "alice")
    keygen.save_keypair(bob_priv, bob_pub, "keys", "bob")
    print("\n✅ Keys saved to keys/ directory")

    # Load
    alice_priv2, alice_pub2 = keygen.load_keypair("keys", "alice")
    fp_match = keygen.get_key_fingerprint(alice_pub) == keygen.get_key_fingerprint(alice_pub2)
    print(f"✅ Keys loaded — fingerprint match: {fp_match}")


if __name__ == "__main__":
    main()

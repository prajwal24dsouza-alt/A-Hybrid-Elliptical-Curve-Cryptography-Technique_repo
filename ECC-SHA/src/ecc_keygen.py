"""
ECC Key Generation Module
=========================
Provides the ``ECCKeyGenerator`` class for Elliptic Curve key pair
management: generation, PEM export/import, file persistence, and
SHA-256 fingerprinting.

Supported curves:
    - SECP256R1 (NIST P-256)  — default
    - SECP384R1 (NIST P-384)

Example::

    keygen = ECCKeyGenerator()
    private_key, public_key = keygen.generate_keypair()
    fingerprint = keygen.get_key_fingerprint(public_key)
    keygen.save_keypair(private_key, public_key, identifier="alice")
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path


class ECCKeyGenerator:
    """Generate, serialise, store and fingerprint ECC key pairs.

    Args:
        curve: An ``ec.EllipticCurve`` instance.  Defaults to SECP256R1.
    """

    SUPPORTED_CURVES = {
        "P-256": ec.SECP256R1,
        "P-384": ec.SECP384R1,
    }

    def __init__(self, curve=None):
        self.curve = curve or ec.SECP256R1()
        self.backend = default_backend()

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------
    def generate_keypair(self):
        """Generate an ECC public/private key pair.

        Returns:
            tuple: ``(private_key, public_key)`` — cryptography key objects.

        Example::

            >>> keygen = ECCKeyGenerator()
            >>> priv, pub = keygen.generate_keypair()
        """
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    # ------------------------------------------------------------------
    # PEM export
    # ------------------------------------------------------------------
    def export_private_key(self, private_key, password=None):
        """Serialise a private key to PEM bytes.

        Args:
            private_key: A ``cryptography`` ECC private key object.
            password (bytes | None): Optional passphrase for PKCS8 encryption.

        Returns:
            bytes: PEM-encoded private key.
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def export_public_key(self, public_key):
        """Serialise a public key to PEM bytes.

        Args:
            public_key: A ``cryptography`` ECC public key object.

        Returns:
            bytes: PEM-encoded public key.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # ------------------------------------------------------------------
    # PEM import
    # ------------------------------------------------------------------
    def import_private_key(self, key_data, password=None):
        """Load a private key from PEM bytes.

        Args:
            key_data (bytes): PEM-encoded private key.
            password (bytes | None): Passphrase if the key is encrypted.

        Returns:
            Private key object.
        """
        return serialization.load_pem_private_key(
            key_data, password=password, backend=self.backend
        )

    def import_public_key(self, key_data):
        """Load a public key from PEM bytes.

        Args:
            key_data (bytes): PEM-encoded public key.

        Returns:
            Public key object.
        """
        return serialization.load_pem_public_key(key_data, backend=self.backend)

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------
    def save_keypair(self, private_key, public_key, key_dir="keys", identifier="user"):
        """Persist a key pair as PEM files.

        Args:
            private_key: ECC private key object.
            public_key: ECC public key object.
            key_dir (str): Directory to write into (created if missing).
            identifier (str): Filename prefix, e.g. ``"alice"``.

        Returns:
            dict: ``{"private": Path, "public": Path}`` of written files.
        """
        key_path = Path(key_dir)
        key_path.mkdir(parents=True, exist_ok=True)

        priv_file = key_path / f"{identifier}_private.pem"
        pub_file = key_path / f"{identifier}_public.pem"

        priv_file.write_bytes(self.export_private_key(private_key))
        pub_file.write_bytes(self.export_public_key(public_key))

        return {"private": priv_file, "public": pub_file}

    def load_keypair(self, key_dir="keys", identifier="user", password=None):
        """Load a key pair from PEM files.

        Args:
            key_dir (str): Directory containing the PEM files.
            identifier (str): Filename prefix used during save.
            password (bytes | None): Passphrase for the private key.

        Returns:
            tuple: ``(private_key, public_key)``

        Raises:
            FileNotFoundError: If either PEM file is missing.
        """
        key_path = Path(key_dir)
        priv_file = key_path / f"{identifier}_private.pem"
        pub_file = key_path / f"{identifier}_public.pem"

        private_key = self.import_private_key(priv_file.read_bytes(), password)
        public_key = self.import_public_key(pub_file.read_bytes())

        return private_key, public_key

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------
    def get_key_fingerprint(self, public_key):
        """Compute a 16-character hex fingerprint of a public key.

        The fingerprint is the first 8 bytes (16 hex chars) of the SHA-256
        digest of the DER-encoded public key.

        Args:
            public_key: ECC public key object.

        Returns:
            str: 16-character hexadecimal fingerprint.
        """
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA256(), self.backend)
        digest.update(pub_bytes)
        full_hash = digest.finalize()
        return full_hash[:8].hex()  # first 8 bytes → 16 hex chars


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    from src.utils import print_header, print_step, print_result

    print_header("ECC Key Generation — Module 1 Demo")

    keygen = ECCKeyGenerator()

    print_step(1, "Generating keypair…")
    priv, pub = keygen.generate_keypair()
    print_result("Generated", f"Private={type(priv).__name__}, Public={type(pub).__name__}")

    print_step(2, "Getting fingerprint…")
    fp = keygen.get_key_fingerprint(pub)
    print_result("Fingerprint", fp)

    print_step(3, "Exporting to PEM…")
    priv_pem = keygen.export_private_key(priv)
    pub_pem = keygen.export_public_key(pub)
    print_result("Private PEM", f"{len(priv_pem)} bytes, starts with {priv_pem[:27].decode()}")
    print_result("Public PEM", f"{len(pub_pem)} bytes, starts with {pub_pem[:26].decode()}")

    print_step(4, "Import round-trip…")
    priv_loaded = keygen.import_private_key(priv_pem)
    pub_loaded = keygen.import_public_key(pub_pem)
    fp_loaded = keygen.get_key_fingerprint(pub_loaded)
    print_result("Fingerprints match", fp == fp_loaded)

    print_step(5, "Saving keys to disk…")
    paths = keygen.save_keypair(priv, pub, "keys", "alice")
    print_result("Private key file", paths["private"])
    print_result("Public key file", paths["public"])

    print_step(6, "Loading keys from disk…")
    priv_disk, pub_disk = keygen.load_keypair("keys", "alice")
    fp_disk = keygen.get_key_fingerprint(pub_disk)
    print_result("Fingerprints match", fp == fp_disk)

    print("\n✅  Module 1 — Complete!\n")

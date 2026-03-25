# Hybrid ECC — Secure Communication

A production-ready **Hybrid Elliptic Curve Cryptography** system implementing
**ECIES encryption** and **ECDSA digital signatures** for secure end-to-end
communication.

## ✨ Features

| Feature | Algorithm | Standard |
|---|---|---|
| Key agreement | ECDH | NIST P-256 / P-384 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Digital signatures | ECDSA-SHA256 | FIPS 186-4 |
| Key serialisation | PEM (PKCS8) | RFC 5958 |

## 📦 Project Structure

```
kkkk/
├── src/
│   ├── ecc_keygen.py           ← Module 1: Key Generation
│   ├── hybrid_encryption.py    ← Module 2: ECIES Encryption
│   ├── digital_signature.py    ← Module 3: ECDSA Signatures
│   ├── secure_channel.py       ← Module 4: Secure Channel Protocol
│   └── utils.py                ← Shared helpers
├── tests/                      ← 25+ automated tests
├── examples/                   ← Runnable demo scripts
├── keys/                       ← Generated key files (gitignored)
└── requirements.txt
```

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v

# Run the Alice–Bob demo
python -m src.secure_channel

# Run example scripts
python examples/simple_encryption.py
python examples/key_management.py
python examples/alice_bob_demo.py
```

## 🔐 Architecture

```
Sender                                              Receiver
──────                                              ────────
1. Generate ephemeral ECC keypair
2. ECDH(ephemeral_priv, recipient_pub) → shared_secret
3. HKDF(shared_secret)                → AES-256 key
4. AES-GCM(plaintext, AES_key)        → ciphertext + tag
5. ECDSA-sign(plaintext, sender_priv)  → signature
6. JSON envelope { ciphertext, tag, iv, ephemeral_pub, signature }
                                                    7. ECDH(recipient_priv, ephemeral_pub)
                                                    8. HKDF → same AES key
                                                    9. AES-GCM decrypt → plaintext
                                                   10. ECDSA verify(signature, sender_pub)
```

## 🧪 Testing

```bash
# Unit + integration + performance
python -m pytest tests/ -v --tb=short

# With coverage report
python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

## 📝 License

MIT

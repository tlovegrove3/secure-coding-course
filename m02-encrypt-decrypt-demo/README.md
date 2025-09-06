# Encryption/Decryption Demo

## Purpose
Demonstrates symmetric and asymmetric encryption methods plus cryptographic hashing using only Python's standard library.

## Requirements
- Python 3.7+
- No external dependencies required (uses standard library)

## Usage
```bash
python encrypt_decrypt_demo.py
```

## What it demonstrates
- **Symmetric Encryption**: Uses XOR cipher with a randomly generated key
- **Asymmetric Encryption**: Uses simplified RSA with small prime numbers for demonstration
- **Cryptographic Hashing**: Shows MD5, SHA-1, and SHA-256 hash functions
- Shows keys, inputs, and outputs for all methods
- Verifies successful encryption/decryption

## Output
The program displays:

### Symmetric Encryption Demo
- Original message
- Randomly generated symmetric key
- Encrypted message (Base64 encoded)
- Decrypted message
- Success verification

### Asymmetric Encryption Demo
- Original message converted to numbers
- Generated prime numbers (p, q)
- Public key (e, n) and Private key (d, n)
- Encrypted numbers
- Decrypted numbers and message
- Success verification

### Cryptographic Hashing Demo
- Original message
- MD5, SHA-1, and SHA-256 hashes
- Demonstration of deterministic hashing
- Avalanche effect example

## Educational Notes
- **XOR Cipher**: Simple symmetric encryption for demonstration only (not secure for production)
- **Simplified RSA**: Uses small numbers to show RSA concepts clearly (production RSA uses 2048+ bit keys)
- **Hashing**: Shows one-way cryptographic functions used for integrity and password storage

## Author
Terry Lovegrove - 2025-09-06

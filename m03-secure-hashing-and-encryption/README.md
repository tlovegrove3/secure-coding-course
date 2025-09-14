# Module 03: Secure Hashing and Encryption

This module contains demonstrations of secure hashing techniques and encryption methods commonly used in cybersecurity.

## Files

### `sha_256_hash.py`

A secure SHA-256 hash generator that follows industry best practices.

**Features:**

- Generate SHA-256 hashes for strings and files
- Memory-efficient chunked file processing
- Input validation and security controls
- Rate limiting and comprehensive error handling

**Usage:**

```bash
# Hash a string
python sha_256_hash.py --string "Hello, World!"

# Hash a file
python sha_256_hash.py --file document.txt

# Quiet mode (no logging)
python sha_256_hash.py --string "message" --quiet
```

### `caesar_cipher.py`

A simple Caesar cipher implementation for educational purposes.

**Features:**

- Encrypt/decrypt text using Caesar cipher
- Supports positive and negative shift values
- Handles alphabetic characters and preserves non-alphabetic characters

**Usage:**

```bash
python caesar_cipher.py
# Follow prompts to enter message and shift key
```

### `digital_signature.py`

OpenSSL-based digital signature demonstration for signing and verifying documents.

**Features:**

- Generate RSA key pairs
- Create digital signatures for files
- Verify digital signatures
- Secure key management practices

**Usage:**

```bash
# Generate key pair
python digital_signature.py --generate-keys

# Sign a file
python digital_signature.py --sign --file document.txt

# Verify a signature
python digital_signature.py --verify --file document.txt --signature document.txt.sig
```

## Security Learning Objectives

1. **Hashing**: Understanding cryptographic hash functions and their properties
2. **Classic Ciphers**: Historical encryption methods and their weaknesses
3. **Digital Signatures**: Public key cryptography for authentication and non-repudiation
4. **Key Management**: Secure generation, storage, and handling of cryptographic keys

## Prerequisites

- Python 3.7+
- Required packages: Install with `pip install -r requirements.txt`

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install cryptography directly
pip install cryptography>=45.0.0
```

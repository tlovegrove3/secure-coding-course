# Secure Coding Course

A comprehensive collection of cybersecurity demonstrations and secure coding practices implemented in Python.

## Modules

### [Module 01: RBAC Authentication Demo](m01-rbac-auth-demo/)

Role-Based Access Control implementation with user authentication and authorization.

### [Module 02: Encrypt/Decrypt Demo](m02-encrypt-decrypt-demo/)

Demonstrations of symmetric and asymmetric encryption methods using Python's standard library.

### [Module 03: Secure Hashing and Encryption](m03-secure-hashing-and-encryption/)

Advanced cryptographic implementations including SHA-256 hashing, Caesar cipher, and digital signatures.

## Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/tlovegrove3/secure-coding-course.git
   cd secure-coding-course
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run any module**

   ```bash
   cd m03-secure-hashing-and-encryption
   python sha_256_hash.py --help
   ```

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Security Notes

⚠️ **Important**: This repository is for educational purposes. Always follow security best practices in production environments:

- Never commit private keys or secrets to version control
- Use environment variables for sensitive configuration
- Keep dependencies updated
- Follow principle of least privilege
- Implement proper input validation and error handling

## Contributing

This is an educational repository. Please ensure any contributions maintain security best practices and include proper documentation.
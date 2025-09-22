# Crypto Integrity Project

A secure cryptographic application demonstrating the CIA triad (Confidentiality, Integrity, Availability) through SHA-256 hashing and AES-256 encryption.

## Features

- **SHA-256 hashing** for data integrity verification
- **AES-256-GCM encryption** for confidentiality with built-in authentication
- **Complete workflow** supporting both text messages and file encryption
- **Security validation** that detects tampering and unauthorized modifications
- **CLI interface** for easy demonstration and practical use

## Requirements

- Python 3.12+
- UV package manager

## Installation

1. **Install UV** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Clone and setup the project**:
   ```bash
   git clone <your-repo-url>
   cd crypto-integrity-project
   uv sync
   ```

## Usage

The application provides three main operations:

### Encrypt and decrypt a text message
```bash
uv run python -m src.crypto_project.main --message "Your secret message here"
```

### Encrypt a file
```bash
uv run python -m src.crypto_project.main --encrypt path/to/your/file.txt
```
This creates a `file.txt.secured` package containing all cryptographic components.

### Decrypt a secured file
```bash
uv run python -m src.crypto_project.main --decrypt path/to/file.txt.secured
```
This recovers the original file as `decrypted_file.txt` after verifying integrity.

### Show help
```bash
uv run python -m src.crypto_project.main --help
```

## How It Works

The application implements a **hash-then-encrypt** security pattern:

1. **Input Processing**: Accepts user messages or file content
2. **Integrity Hashing**: Generates SHA-256 hash of original data
3. **Encryption**: Encrypts data using AES-256 in GCM mode with:
   - Randomly generated 256-bit encryption key
   - Unique initialization vector (IV) for each operation
   - Authentication tag for tamper detection
4. **Verification**: During decryption, verifies both cryptographic authenticity (GCM) and data integrity (SHA-256)

## Security Properties

### How This Solution Upholds the CIA Triad

**🔐 Confidentiality**  
Data confidentiality is achieved through AES-256 encryption in GCM mode. The original plaintext is transformed into ciphertext using a 256-bit encryption key, making it computationally infeasible for unauthorized parties to read the data without the key. Even with access to the encrypted file, attackers cannot derive meaningful information from the random-appearing ciphertext.

**🛡️ Integrity**  
Data integrity is ensured through a two-layer approach:
1. **SHA-256 hashing**: Creates a unique 256-bit fingerprint of the original data before encryption
2. **GCM authentication**: Provides built-in authentication tags that detect any modifications to the ciphertext

If even a single bit is modified in either the original data or the encrypted data, the verification process will fail, alerting users to potential tampering or corruption.

**🚀 Availability**  
Data availability is maintained by ensuring authorized users can reliably decrypt and access their information. The system stores all necessary cryptographic components (encrypted data, hash, key, IV, authentication tag) in a structured format, enabling consistent decryption across different systems and time periods.

### Role of Entropy and Key Generation

**Entropy Sources**  
This implementation uses Python's `secrets` module, which leverages the operating system's cryptographically secure random number generator (CSPRNG). On modern systems, this draws entropy from hardware sources such as:
- CPU thermal noise and timing variations
- Mouse movements and keyboard timings  
- Hardware random number generators (if available)
- System interrupt timing variations

**Key Generation Process**  
1. **AES-256 Keys**: Generated using `secrets.token_bytes(32)` to produce 256 bits of cryptographic randomness
2. **Initialization Vectors (IVs)**: Created using `os.urandom(16)` for each encryption operation, ensuring unique ciphertext even for identical plaintexts
3. **Salt Generation**: When used, employs `secrets.token_bytes(32)` for hash salting

**Security Significance**  
High-quality entropy is critical because:
- **Unpredictable keys** prevent brute-force and dictionary attacks
- **Unique IVs** ensure semantic security (same plaintext produces different ciphertext)
- **Cryptographic randomness** resists statistical analysis and pattern detection

The use of cryptographically secure sources (rather than pseudorandom generators like `random.random()`) ensures that keys cannot be predicted or reproduced by attackers, maintaining the fundamental security assumptions of the cryptographic algorithms.

## Example Output

```
🔒 === CRYPTOGRAPHIC MESSAGE PROCESSING ===
📝 Original message: Secret launch codes: Alpha-7-Charlie
📏 Message length: 38 characters

🔐 --- SECURING MESSAGE ---
✅ Message secured successfully!
🔑 Encryption key: 4d3f0fb5b1b0dd603e3aa952af796312...
🏷️  Integrity hash: 63cc31d019f55b7e...
🔒 Encrypted data: f8a615a3af5dffd94e8832273e8430ed...

🔓 --- VERIFYING AND DECRYPTING ---
🔍 Integrity verification: ✅ PASSED
📝 Decrypted message: Secret launch codes: Alpha-7-Charlie
✅ Round-trip success: True

🎉 CIA TRIAD ACHIEVED:
   📊 Confidentiality: Message encrypted with AES-256
   🛡️  Integrity: SHA-256 hash verified no tampering
   🚀 Availability: Authorized decryption successful
```

## Project Structure

```
crypto-integrity-project/
├── src/crypto_project/
│   ├── hashing.py          # SHA-256 implementation
│   ├── encryption.py       # AES-256 implementation
│   ├── integrity.py        # Combined workflow
│   └── main.py            # CLI interface
├── tests/                 # Test files
├── pyproject.toml         # Project configuration
└── README.md             # This file
```

## Dependencies

- `cryptography` - Industry-standard cryptographic library
- `secrets` - Cryptographically secure random number generation

All dependencies are automatically managed by UV.
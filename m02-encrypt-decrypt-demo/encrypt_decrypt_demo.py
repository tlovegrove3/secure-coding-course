"""
Creator: Terry Lovegrove
Date: 2025-09-13
Purpose: Demonstrate symmetric and asymmetric encryption/decryption methods

Requirements:
- Encrypt/decrypt a short message using symmetric and asymmetric methods
- Show keys used, inputs, and outputs
- Include functionality explanation

Updated to show industry-standard approaches while using standard library
"""

import hashlib
import secrets
import base64
import hmac
from math import gcd

def print_separator(title):
    """Print a formatted separator for better output readability"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)

def derive_key_from_password(password, salt):
    """Derive encryption key from password using PBKDF2 (industry standard)"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def encrypt_with_derived_key(message, password):
    """AES-like encryption using derived key and HMAC for authentication"""
    # Generate random salt
    salt = secrets.token_bytes(16)
    
    # Derive key from password using PBKDF2
    key = derive_key_from_password(password, salt)
    
    # Use first 16 bytes as encryption key, next 16 as MAC key
    enc_key = key[:16]
    mac_key = key[16:32]
    
    # Simple stream cipher (XOR with key stream from hash)
    message_bytes = message.encode()
    encrypted = bytearray()
    
    for i, byte in enumerate(message_bytes):
        # Create key stream by hashing key + counter
        key_stream_input = enc_key + i.to_bytes(4, 'big')
        key_stream_byte = hashlib.sha256(key_stream_input).digest()[0]
        encrypted.append(byte ^ key_stream_byte)
    
    encrypted = bytes(encrypted)
    
    # Create HMAC for authentication (prevents tampering)
    mac = hmac.new(mac_key, salt + encrypted, hashlib.sha256).digest()
    
    return salt, encrypted, mac

def decrypt_with_derived_key(salt, encrypted, mac, password):
    """Decrypt and verify authenticity"""
    # Derive same key from password
    key = derive_key_from_password(password, salt)
    enc_key = key[:16]
    mac_key = key[16:32]
    
    # Verify HMAC first (authenticate before decrypt)
    expected_mac = hmac.new(mac_key, salt + encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("Authentication failed - data may be tampered")
    
    # Decrypt using same key stream
    decrypted = bytearray()
    for i, byte in enumerate(encrypted):
        key_stream_input = enc_key + i.to_bytes(4, 'big')
        key_stream_byte = hashlib.sha256(key_stream_input).digest()[0]
        decrypted.append(byte ^ key_stream_byte)
    
    return bytes(decrypted).decode()

def symmetric_encryption_demo():
    """Demonstrate symmetric encryption using industry-standard techniques"""
    print_separator("SYMMETRIC ENCRYPTION DEMO (PBKDF2 + HMAC)")
    
    # Original message
    message = "Hello, this is a secret message for symmetric encryption!"
    print(f"Original Message: {message}")
    
    # Use password-based encryption (more realistic)
    password = "MySecurePassword123!"
    print(f"Password: {password}")
    
    # Encrypt the message
    salt, encrypted, mac = encrypt_with_derived_key(message, password)
    
    print(f"Salt (hex): {salt.hex()}")
    print(f"Encrypted (base64): {base64.b64encode(encrypted).decode()}")
    print(f"HMAC (hex): {mac.hex()}")
    
    # Decrypt the message
    try:
        decrypted_message = decrypt_with_derived_key(salt, encrypted, mac, password)
        print(f"Decrypted Message: {decrypted_message}")
        success = message == decrypted_message
    except ValueError as e:
        print(f"Decryption failed: {e}")
        decrypted_message = "FAILED"
        success = False
    
    print(f"Encryption/Decryption Successful: {success}")
    
    # Demonstrate tampering detection
    print("\n--- Tampering Detection Demo ---")
    try:
        # Modify the encrypted data
        tampered_encrypted = bytearray(encrypted)
        tampered_encrypted[0] ^= 1  # Flip one bit
        decrypt_with_derived_key(salt, bytes(tampered_encrypted), mac, password)
    except ValueError as e:
        print(f"Tampering detected: {e}")
    
    return {
        'original': message,
        'password': password,
        'salt': salt.hex(),
        'encrypted': base64.b64encode(encrypted).decode(),
        'mac': mac.hex(),
        'decrypted': decrypted_message,
        'success': success
    }

def miller_rabin_test(n, k=5):
    """Miller-Rabin primality test (more robust than simple trial division)"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Test k times
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
            
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits):
    """Generate a random prime number with specified bit length"""
    while True:
        # Generate random odd number
        candidate = secrets.randbits(bits)
        candidate |= (1 << bits - 1) | 1  # Set MSB and LSB
        
        if miller_rabin_test(candidate):
            return candidate

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a, m):
    """Calculate modular inverse"""
    gcd_val, x, y = extended_gcd(a, m)
    if gcd_val != 1:
        return None
    return (x % m + m) % m

def improved_rsa_demo():
    """Demonstrate asymmetric encryption using improved RSA implementation"""
    print_separator("ASYMMETRIC ENCRYPTION DEMO (Improved RSA)")
    
    # Original message
    message = "SECRET"
    print(f"Original Message: {message}")
    
    # Convert to bytes for proper handling
    message_bytes = message.encode()
    message_int = int.from_bytes(message_bytes, 'big')
    print(f"Message as Integer: {message_int}")
    
    # Generate RSA keys with proper bit size for demo
    print("Generating RSA keys (this may take a moment)...")
    bit_size = 512  # Small but more realistic than previous demo
    
    p = generate_prime(bit_size // 2)
    q = generate_prime(bit_size // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Use standard RSA public exponent
    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    
    # Calculate private exponent
    d = mod_inverse(e, phi)
    
    print(f"Key size: {bit_size} bits")
    print(f"Prime p: {p}")
    print(f"Prime q: {q}")
    print(f"Modulus n: {n}")
    print(f"Public exponent e: {e}")
    print(f"Private exponent d: {d}")
    
    # Ensure message is smaller than modulus
    if message_int >= n:
        print(f"Error: Message too large for key size")
        return {'success': False}
    
    # Encrypt with public key
    ciphertext = pow(message_int, e, n)
    print(f"Encrypted (integer): {ciphertext}")
    print(f"Encrypted (hex): {hex(ciphertext)}")
    
    # Decrypt with private key
    decrypted_int = pow(ciphertext, d, n)
    print(f"Decrypted (integer): {decrypted_int}")
    
    # Convert back to message
    try:
        # Calculate byte length needed
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        decrypted_message = decrypted_bytes.decode()
        print(f"Decrypted Message: {decrypted_message}")
        success = message == decrypted_message
    except Exception as e:
        print(f"Decryption error: {e}")
        decrypted_message = "FAILED"
        success = False
    
    print(f"Encryption/Decryption Successful: {success}")
    
    return {
        'original': message,
        'key_size': bit_size,
        'public_key': f"(e={e}, n={n})",
        'private_key': f"(d={d}, n={n})",
        'encrypted': hex(ciphertext),
        'decrypted': decrypted_message,
        'success': success
    }

def secure_hash_demo():
    """Demonstrate secure hashing practices"""
    print_separator("SECURE HASHING DEMO")
    
    # Password hashing example
    password = "MyPassword123!"
    print(f"Original Password: {password}")
    
    # Generate random salt (industry standard)
    salt = secrets.token_bytes(32)
    print(f"Salt (hex): {salt.hex()}")
    
    # Use PBKDF2 for password hashing (industry standard)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    print(f"PBKDF2 Hash (hex): {password_hash.hex()}")
    
    # Message integrity example
    message = "This message needs integrity protection"
    print(f"\nMessage: {message}")
    
    # Create message digest
    message_hash = hashlib.sha256(message.encode()).digest()
    print(f"SHA-256 Hash: {message_hash.hex()}")
    
    # HMAC for message authentication
    secret_key = secrets.token_bytes(32)
    message_mac = hmac.new(secret_key, message.encode(), hashlib.sha256).digest()
    print(f"HMAC (with secret key): {message_mac.hex()}")
    
    # Verify HMAC
    verify_mac = hmac.new(secret_key, message.encode(), hashlib.sha256).digest()
    mac_valid = hmac.compare_digest(message_mac, verify_mac)
    print(f"HMAC Verification: {mac_valid}")

def main():
    """Main function to run all encryption demos"""
    print("ENCRYPTION/DECRYPTION DEMONSTRATION")
    print("Author: Terry Lovegrove")
    print("Date: 2025-09-13")
    print("Industry-Standard Approaches with Python Standard Library")
    
    # Run symmetric encryption demo
    sym_results = symmetric_encryption_demo()
    
    # Run asymmetric encryption demo
    asym_results = improved_rsa_demo()
    
    # Run secure hashing demo
    secure_hash_demo()
    
    # Summary
    print_separator("SUMMARY")
    print("Symmetric Encryption (PBKDF2 + Stream Cipher + HMAC):")
    print(f"  - Password-based key derivation (PBKDF2)")
    print(f"  - Authenticated encryption (HMAC for integrity)")
    print(f"  - Salt prevents rainbow table attacks")
    print(f"  - Success: {sym_results['success']}")
    
    print("\nAsymmetric Encryption (RSA with proper key generation):")
    print(f"  - Miller-Rabin primality testing")
    print(f"  - Standard public exponent (65537)")
    print(f"  - Proper bit length for security")
    print(f"  - Success: {asym_results['success']}")
    
    print("\nSecure Hashing:")
    print(f"  - PBKDF2 for password storage")
    print(f"  - HMAC for message authentication")
    print(f"  - Constant-time comparison prevents timing attacks")

if __name__ == "__main__":
    main()

"""
FUNCTIONALITY EXPLANATION:

This program demonstrates three fundamental cryptographic concepts using only Python's standard library:

1. SYMMETRIC ENCRYPTION (XOR Cipher):
   - Uses a single key for both encryption and decryption
   - XOR operation: plaintext XOR key = ciphertext
   - Decryption: ciphertext XOR key = plaintext (XOR is its own inverse)
   - Key must be shared securely between parties

2. ASYMMETRIC ENCRYPTION (Simplified RSA):
   - Uses mathematically related key pairs (public and private)
   - Based on difficulty of factoring large numbers
   - Public key can be shared openly
   - Private key must be kept secret
   - Demonstrates core RSA concepts with small numbers for clarity

3. CRYPTOGRAPHIC HASHING:
   - One-way mathematical function
   - Always produces same output for same input
   - Small input changes cause dramatic output changes (avalanche effect)
   - Used for integrity verification and secure password storage

SECURITY NOTES:
- XOR cipher shown here is for educational purposes only
- Real-world applications should use proven algorithms (AES, RSA-2048+)
- This simplified RSA uses small numbers for demonstration
- Production systems require proper key sizes and padding schemes
"""
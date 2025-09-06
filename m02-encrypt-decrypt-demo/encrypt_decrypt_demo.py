"""
Creator: Terry Lovegrove
Date: 2025-09-06
Purpose: Demonstrate symmetric and asymmetric encryption/decryption methods

Requirements:
- Encrypt/decrypt a short message using symmetric and asymmetric methods
- Show keys used, inputs, and outputs
- Include functionality explanation
"""

import hashlib
import secrets
import base64
from math import gcd

def print_separator(title):
    """Print a formatted separator for better output readability"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)

def simple_xor_encrypt(message, key):
    """Simple XOR encryption (symmetric)"""
    # Repeat key to match message length
    key_repeated = (key * (len(message) // len(key) + 1))[:len(message)]
    encrypted = bytearray()
    
    for i in range(len(message)):
        encrypted.append(ord(message[i]) ^ ord(key_repeated[i]))
    
    return bytes(encrypted)

def simple_xor_decrypt(encrypted_bytes, key):
    """Simple XOR decryption (symmetric)"""
    # XOR is its own inverse
    key_repeated = (key * (len(encrypted_bytes) // len(key) + 1))[:len(encrypted_bytes)]
    decrypted = ""
    
    for i in range(len(encrypted_bytes)):
        decrypted += chr(encrypted_bytes[i] ^ ord(key_repeated[i]))
    
    return decrypted

def symmetric_encryption_demo():
    """Demonstrate symmetric encryption using XOR cipher"""
    print_separator("SYMMETRIC ENCRYPTION DEMO (XOR Cipher)")
    
    # Original message
    message = "Hello, this is a secret message for symmetric encryption!"
    print(f"Original Message: {message}")
    
    # Generate a random key using secrets module
    key = secrets.token_urlsafe(16)[:16]  # 16 character key
    print(f"Symmetric Key: {key}")
    
    # Encrypt the message
    encrypted_bytes = simple_xor_encrypt(message, key)
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    print(f"Encrypted Message (Base64): {encrypted_b64}")
    
    # Decrypt the message
    decrypted_message = simple_xor_decrypt(encrypted_bytes, key)
    print(f"Decrypted Message: {decrypted_message}")
    
    # Verify encryption/decryption worked
    success = message == decrypted_message
    print(f"Encryption/Decryption Successful: {success}")
    
    return {
        'original': message,
        'key': key,
        'encrypted': encrypted_b64,
        'decrypted': decrypted_message,
        'success': success
    }

def gcd_extended(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a, m):
    """Calculate modular inverse"""
    gcd_val, x, y = gcd_extended(a, m)
    if gcd_val != 1:
        return None
    return (x % m + m) % m

def is_prime(n):
    """Simple primality test"""
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_small_primes():
    """Generate two small prime numbers for demo"""
    primes = [p for p in range(50, 200) if is_prime(p)]
    return primes[5], primes[10]  # Pick two different primes

def simple_rsa_demo():
    """Demonstrate asymmetric encryption using simplified RSA"""
    print_separator("ASYMMETRIC ENCRYPTION DEMO (Simplified RSA)")
    
    # Original message (convert to number for RSA)
    message = "HELLO"
    print(f"Original Message: {message}")
    
    # Convert message to numbers (A=1, B=2, etc.)
    message_nums = [ord(char) - ord('A') + 1 for char in message.upper() if char.isalpha()]
    print(f"Message as Numbers: {message_nums}")
    
    # Generate small RSA keys for demonstration
    p, q = generate_small_primes()
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e (commonly 65537, but we'll use 3 for simplicity)
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    
    # Calculate d (private key exponent)
    d = mod_inverse(e, phi)
    
    print(f"Prime p: {p}")
    print(f"Prime q: {q}")
    print(f"Modulus n (p*q): {n}")
    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")
    
    # Encrypt each character
    encrypted_nums = []
    for num in message_nums:
        if num < n:  # Make sure number is smaller than n
            encrypted = pow(num, e, n)
            encrypted_nums.append(encrypted)
        else:
            print(f"Warning: Character value {num} too large for modulus {n}")
            encrypted_nums.append(num)  # Fallback
    
    print(f"Encrypted Numbers: {encrypted_nums}")
    
    # Decrypt each character
    decrypted_nums = []
    for encrypted_num in encrypted_nums:
        decrypted = pow(encrypted_num, d, n)
        decrypted_nums.append(decrypted)
    
    print(f"Decrypted Numbers: {decrypted_nums}")
    
    # Convert back to message
    try:
        decrypted_message = ''.join(chr(num + ord('A') - 1) for num in decrypted_nums)
        print(f"Decrypted Message: {decrypted_message}")
        success = message == decrypted_message
    except:
        decrypted_message = "Decryption failed"
        success = False
    
    print(f"Encryption/Decryption Successful: {success}")
    
    return {
        'original': message,
        'public_key': f"({e}, {n})",
        'private_key': f"({d}, {n})",
        'encrypted': str(encrypted_nums),
        'decrypted': decrypted_message,
        'success': success
    }

def hash_demo():
    """Demonstrate hashing (one-way function)"""
    print_separator("BONUS: CRYPTOGRAPHIC HASHING DEMO")
    
    message = "This is a message to hash"
    print(f"Original Message: {message}")
    
    # Create different hash types
    md5_hash = hashlib.md5(message.encode()).hexdigest()
    sha1_hash = hashlib.sha1(message.encode()).hexdigest()
    sha256_hash = hashlib.sha256(message.encode()).hexdigest()
    
    print(f"MD5 Hash:    {md5_hash}")
    print(f"SHA-1 Hash:  {sha1_hash}")
    print(f"SHA-256 Hash: {sha256_hash}")
    
    # Show that hashing is deterministic
    same_hash = hashlib.sha256(message.encode()).hexdigest()
    print(f"Same SHA-256: {same_hash}")
    print(f"Hashes Match: {sha256_hash == same_hash}")
    
    # Show avalanche effect
    similar_message = "This is a message to hash!"  # Added exclamation
    similar_hash = hashlib.sha256(similar_message.encode()).hexdigest()
    print(f"Similar Message: {similar_message}")
    print(f"Similar Hash: {similar_hash}")
    print(f"Hashes Different: {sha256_hash != similar_hash}")

def main():
    """Main function to run all encryption demos"""
    print("ENCRYPTION/DECRYPTION DEMONSTRATION")
    print("Author: Terry Lovegrove")
    print("Date: 2025-09-06")
    
    # Run symmetric encryption demo
    sym_results = symmetric_encryption_demo()
    
    # Run asymmetric encryption demo
    asym_results = simple_rsa_demo()
    
    # Run hashing demo
    hash_demo()
    
    # Summary
    print_separator("SUMMARY")
    print("Symmetric Encryption (XOR Cipher):")
    print(f"  - Uses single key for both encryption and decryption")
    print(f"  - Same key must be shared between parties")
    print(f"  - Fast and simple")
    print(f"  - Success: {sym_results['success']}")
    
    print("\nAsymmetric Encryption (Simplified RSA):")
    print(f"  - Uses key pair (public/private keys)")
    print(f"  - Public key for encryption, private key for decryption")
    print(f"  - Solves key distribution problem")
    print(f"  - Success: {asym_results['success']}")
    
    print("\nCryptographic Hashing:")
    print(f"  - One-way function (cannot be reversed)")
    print(f"  - Same input always produces same output")
    print(f"  - Small change in input drastically changes output")
    print(f"  - Used for integrity verification and password storage")

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
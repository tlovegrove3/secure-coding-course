"""Manual testing script to see our crypto functions in action."""

from src.crypto_project.hashing import HashingService
from src.crypto_project.encryption import EncryptionService

def test_hashing():
    """Test the hashing functionality."""
    hasher = HashingService()
    
    # Test with some sample data
    test_message = "Hello, Secure World!"
    test_bytes = test_message.encode('utf-8')
    
    print("=== SHA-256 Hashing Demo ===")
    print(f"Original message: {test_message}")
    print(f"Message as bytes: {test_bytes}")
    
    # Generate hash
    hash_result = hasher.hash_data(test_bytes)
    print(f"SHA-256 hash: {hash_result}")
    print(f"Hash length: {len(hash_result)} characters")
    
    # Test that same input gives same hash (deterministic)
    hash_result2 = hasher.hash_data(test_bytes)
    print(f"Same hash again? {hash_result == hash_result2}")
    
    # Test that small change gives completely different hash
    modified_message = "Hello, Secure World."  # Added a period
    modified_bytes = modified_message.encode('utf-8')
    modified_hash = hasher.hash_data(modified_bytes)
    
    print(f"\nModified message: {modified_message}")
    print(f"Modified hash: {modified_hash}")
    print(f"Hashes are different? {hash_result != modified_hash}")
    
    # Show how different they are
    print(f"\nOriginal:  {hash_result}")
    print(f"Modified:  {modified_hash}")
    print("Notice: Even one character change completely changes the hash!")

def test_verification():
    """Test the hash verification functionality."""
    hasher = HashingService()
    
    print("\n=== Hash Verification Demo ===")
    
    # Test data
    original_data = b"Critical financial data: $1,000,000 transfer"
    print(f"Original data: {original_data.decode()}")
    
    # Generate hash (like storing it securely)
    stored_hash = hasher.hash_data(original_data)
    print(f"Stored hash: {stored_hash}")
    
    # Later... verify the data hasn't been tampered with
    print("\n--- Integrity Check #1: Valid Data ---")
    is_valid = hasher.verify_hash(original_data, stored_hash)
    print(f"Data integrity verified: {is_valid}")
    
    # Test with tampered data
    print("\n--- Integrity Check #2: Tampered Data ---")
    tampered_data = b"Critical financial data: $9,999,999 transfer"  # Amount changed!
    is_valid_tampered = hasher.verify_hash(tampered_data, stored_hash)
    print(f"Tampered data: {tampered_data.decode()}")
    print(f"Data integrity verified: {is_valid_tampered}")
    
    if not is_valid_tampered:
        print("🚨 SECURITY ALERT: Data has been tampered with!")
    
    # Test with wrong hash
    print("\n--- Integrity Check #3: Wrong Hash ---")
    wrong_hash = "1234567890abcdef" * 4  # Fake hash
    is_valid_wrong = hasher.verify_hash(original_data, wrong_hash)
    print(f"Wrong hash provided: {wrong_hash}")
    print(f"Data integrity verified: {is_valid_wrong}")

def test_encryption():
    """Test the AES encryption functionality."""
    encryptor = EncryptionService()
    
    print("\n=== AES-256 Encryption Demo ===")
    
    # Test data - something sensitive
    secret_message = "The missile launch codes are: 1234-5678-9012"
    secret_bytes = secret_message.encode('utf-8')
    print(f"Secret message: {secret_message}")
    print(f"Message length: {len(secret_bytes)} bytes")
    
    # Generate a secure key
    encryption_key = encryptor.generate_key()
    print(f"Generated key: {encryption_key.hex()}")
    print(f"Key length: {len(encryption_key)} bytes (AES-256)")
    
    # Encrypt the data
    print("\n--- Encryption Process ---")
    ciphertext, iv, auth_tag = encryptor.encrypt_data(secret_bytes, encryption_key)
    
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Auth tag: {auth_tag.hex()}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Show that ciphertext looks like random garbage
    try:
        garbled = ciphertext.decode('utf-8', errors='replace')
        print(f"Ciphertext as text: {garbled[:50]}... (unreadable!)")
    except:
        print("Ciphertext is unreadable binary data (good!)")
    
    # Decrypt the data
    print("\n--- Decryption Process ---")
    decrypted_bytes = encryptor.decrypt_data(ciphertext, encryption_key, iv, auth_tag)
    decrypted_message = decrypted_bytes.decode('utf-8')
    
    print(f"Decrypted message: {decrypted_message}")
    print(f"Decryption successful: {decrypted_message == secret_message}")
    
    # Test security: wrong key
    print("\n--- Security Test: Wrong Key ---")
    wrong_key = encryptor.generate_key()  # Different key
    try:
        bad_decrypt = encryptor.decrypt_data(ciphertext, wrong_key, iv, auth_tag)
        print("❌ ERROR: Decryption should have failed!")
    except Exception as e:
        print(f"✅ Good: Wrong key rejected - {type(e).__name__}")
    
    # Test security: tampered data  
    print("\n--- Security Test: Tampered Data ---")
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1  # Flip one bit
    try:
        bad_decrypt = encryptor.decrypt_data(bytes(tampered_ciphertext), encryption_key, iv, auth_tag)
        print("❌ ERROR: Tampered data should have been detected!")
    except Exception as e:
        print(f"✅ Good: Tampering detected - {type(e).__name__}")

def test_encryption_roundtrip():
    """Test that we can encrypt and decrypt various data types."""
    encryptor = EncryptionService()
    
    print("\n=== Encryption Round-trip Tests ===")
    
    test_cases = [
        "Simple text message",
        "Special chars: üñíçødé ñámés! 🔐",
        "Numbers and symbols: 123-456-7890 $#@!",
        "A" * 1000,  # Long message
        "",  # Empty message
        "Sensitive data:\nCredit Card: 4532-1234-5678-9012\nSSN: 123-45-6789"
    ]
    
    key = encryptor.generate_key()
    
    for i, test_message in enumerate(test_cases, 1):
        test_bytes = test_message.encode('utf-8')
        
        # Encrypt
        ciphertext, iv, auth_tag = encryptor.encrypt_data(test_bytes, key)
        
        # Decrypt  
        decrypted_bytes = encryptor.decrypt_data(ciphertext, key, iv, auth_tag)
        decrypted_message = decrypted_bytes.decode('utf-8')
        
        # Verify
        success = test_message == decrypted_message
        print(f"Test {i}: {'✅ PASS' if success else '❌ FAIL'} - {len(test_message)} chars")
        
        if not success:
            print(f"  Expected: {test_message[:50]}...")
            print(f"  Got:      {decrypted_message[:50]}...")

if __name__ == "__main__":
    test_hashing()
    test_verification()
    test_encryption()
    test_encryption_roundtrip()
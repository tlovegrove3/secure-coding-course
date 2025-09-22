"""Manual testing script to see our crypto functions in action."""

from src.crypto_project.hashing import HashingService

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

if __name__ == "__main__":
    test_hashing()
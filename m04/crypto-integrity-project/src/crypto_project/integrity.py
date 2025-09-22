"""Combined integrity verification using hashing and encryption."""

from .hashing import HashingService
from .encryption import EncryptionService
from typing import Any


class IntegrityService:
    """Combines hashing and encryption for complete data protection."""
    
    def __init__(self):
        self.hasher = HashingService()
        self.encryptor = EncryptionService()
    
    def secure_data(self, data: bytes) -> dict[str, Any]:
        """
        Hash then encrypt data, returning all components needed for verification.
        
        This implements the "authenticate-then-encrypt" pattern:
        1. Generate hash of original data (for integrity verification)
        2. Generate encryption key
        3. Encrypt the original data
        4. Return everything needed to verify and decrypt later
        
        Args:
            data: Raw bytes to secure
            
        Returns:
            Dictionary containing:
            - encrypted_data: AES-encrypted ciphertext
            - hash: SHA-256 hash of original data
            - key: AES-256 encryption key
            - iv: Initialization vector used for encryption
            - auth_tag: GCM authentication tag
            
        Example:
            >>> service = IntegrityService()
            >>> result = service.secure_data(b"Secret message")
            >>> type(result)
            <class 'dict'>
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes, not string. Use data.encode() to convert.")
        
        # Step 1: Generate hash of original data for integrity verification
        original_hash = self.hasher.hash_data(data)
        
        # Step 2: Generate encryption key
        encryption_key = self.encryptor.generate_key()
        
        # Step 3: Encrypt the original data
        encrypted_data, iv, auth_tag = self.encryptor.encrypt_data(data, encryption_key)
        
        # Step 4: Return all components
        return {
            "encrypted_data": encrypted_data,
            "hash": original_hash,
            "key": encryption_key,
            "iv": iv,
            "auth_tag": auth_tag
        }
    
    def verify_and_decrypt(self, secured_data: dict[str, Any]) -> tuple[bool, bytes]:
        """
        Decrypt data and verify its integrity.
        
        This implements the verification workflow:
        1. Decrypt the encrypted data
        2. Hash the decrypted data
        3. Compare with stored hash to verify integrity
        4. Return verification result and decrypted data
        
        Args:
            secured_data: Dictionary from secure_data() containing all components
            
        Returns:
            Tuple of (integrity_verified, decrypted_data)
            - integrity_verified: True if hash matches, False if tampered
            - decrypted_data: Original plaintext (even if integrity failed)
            
        Raises:
            KeyError: If required keys missing from secured_data
            InvalidTag: If decryption fails due to wrong key or tampering
        """
        # Extract all components
        encrypted_data = secured_data["encrypted_data"]
        stored_hash = secured_data["hash"]
        key = secured_data["key"]
        iv = secured_data["iv"]
        auth_tag = secured_data["auth_tag"]
        
        # Step 1: Decrypt the data
        # Note: If decryption fails here, it means the ciphertext was tampered with
        # or wrong key/IV/tag provided. GCM mode will raise InvalidTag exception.
        decrypted_data = self.encryptor.decrypt_data(encrypted_data, key, iv, auth_tag)
        
        # Step 2: Verify integrity by re-hashing decrypted data
        current_hash = self.hasher.hash_data(decrypted_data)
        
        # Step 3: Compare hashes directly (more efficient than calling verify_hash)
        integrity_verified = current_hash == stored_hash
        
        return integrity_verified, decrypted_data
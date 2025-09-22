"""AES encryption functionality for confidentiality."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import os


class EncryptionService:
    """Handles AES encryption and decryption."""
    
    def __init__(self):
        self.key_size = 32  # AES-256 (32 bytes = 256 bits)
        self.iv_size = 16   # AES block size (16 bytes = 128 bits)
        self.tag_size = 16  # GCM authentication tag size
    
    def generate_key(self) -> bytes:
        """
        Generate a cryptographically secure AES-256 key.
        
        Returns:
            32 bytes of random data suitable for AES-256
            
        Example:
            >>> encryptor = EncryptionService()
            >>> key = encryptor.generate_key()
            >>> len(key)
            32
        """
        # Use secrets module for cryptographically secure random generation
        # This is much better than random.random() for security purposes
        return secrets.token_bytes(self.key_size)
    
    def encrypt_data(self, data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256 in GCM mode.
        
        GCM mode provides both confidentiality AND authenticity - it's like
        encryption with a built-in tamper-evident seal.
        
        Args:
            data: Raw bytes to encrypt
            key: 32-byte AES-256 key
            
        Returns:
            Tuple of (encrypted_data, iv, auth_tag)
            
        Raises:
            ValueError: If key is wrong size
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be exactly {self.key_size} bytes for AES-256")
        
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes, not string. Use data.encode() to convert.")
        
        # Generate a random IV for this encryption operation
        # CRITICAL: Never reuse an IV with the same key!
        iv = os.urandom(self.iv_size)
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        # Encrypt the data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Get the authentication tag (proves data hasn't been tampered with)
        auth_tag = encryptor.tag
        
        return ciphertext, iv, auth_tag
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes, iv: bytes, auth_tag: bytes) -> bytes:
        """
        Decrypt AES-GCM encrypted data.
        
        Args:
            encrypted_data: The ciphertext to decrypt
            key: 32-byte AES-256 key (same one used for encryption)
            iv: Initialization vector used during encryption
            auth_tag: Authentication tag from encryption
            
        Returns:
            Original plaintext data
            
        Raises:
            ValueError: If key is wrong size
            InvalidTag: If data has been tampered with (authenticity check fails)
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be exactly {self.key_size} bytes for AES-256")
        
        # Create AES-GCM cipher for decryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, auth_tag),  # Must provide the same IV and auth tag
            backend=default_backend()
        )
        
        # Decrypt the data
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # If we get here without an exception, the authenticity check passed!
        return plaintext
#!/usr/bin/env python3
"""
Program: Digital Signature Tool
Author: Terry Lovegrove
Date: 2025-09-14
Description:
A secure implementation of digital signatures using RSA and OpenSSL standards.
Demonstrates signing and verification of files using public-key cryptography.

"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Union, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


class DigitalSignatureTool:
    """
    A digital signature tool implementing industry-standard practices.
    """
    
    # Security constants
    KEY_SIZE = 2048  # RSA key size in bits
    PUBLIC_EXPONENT = 65537  # Standard public exponent
    SIGNATURE_ALGORITHM = hashes.SHA256()  # Hash algorithm for signatures
    SIGNATURE_PADDING = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    
    def __init__(self, enable_logging: bool = True):
        """
        Initialize the digital signature tool.
        
        Args:
            enable_logging (bool): Whether to enable logging
        """
        self.logger = self._setup_logging() if enable_logging else None
        self.private_key = None
        self.public_key = None
    
    def _setup_logging(self) -> logging.Logger:
        """
        Set up secure logging configuration.
        
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger('digital_signature')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _validate_file_path(self, file_path: Union[str, Path]) -> Path:
        """
        Validate and sanitize file path.
        
        Args:
            file_path (Union[str, Path]): File path to validate
            
        Returns:
            Path: Validated path object
            
        Raises:
            ValueError: If path is invalid
            FileNotFoundError: If file doesn't exist
        """
        try:
            path = Path(file_path).resolve()
        except Exception as e:
            raise ValueError(f"Invalid file path: {e}")
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")
        
        return path
    
    def generate_key_pair(self, private_key_path: str = "private_key.pem", 
                         public_key_path: str = "public_key.pem",
                         password: bytes = None) -> Tuple[str, str]:
        """
        Generate an RSA key pair and save to files.
        
        Args:
            private_key_path (str): Path to save private key
            public_key_path (str): Path to save public key
            password (bytes): Optional password to encrypt private key
            
        Returns:
            Tuple[str, str]: Paths to private and public key files
            
        Raises:
            OSError: If file operations fail
        """
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=self.PUBLIC_EXPONENT,
                key_size=self.KEY_SIZE
            )
            
            # Get public key from private key
            public_key = private_key.public_key()
            
            # Serialize private key
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Write keys to files
            private_path = Path(private_key_path)
            public_path = Path(public_key_path)
            
            # Set secure permissions for private key (owner read/write only)
            with open(private_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_path, 0o600)
            
            with open(public_path, 'wb') as f:
                f.write(public_pem)
            
            if self.logger:
                self.logger.info(f"Generated key pair: {private_path}, {public_path}")
            
            return str(private_path), str(public_path)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error generating key pair: {e}")
            raise
    
    def load_private_key(self, private_key_path: str, password: bytes = None):
        """
        Load private key from file.
        
        Args:
            private_key_path (str): Path to private key file
            password (bytes): Optional password for encrypted key
            
        Raises:
            ValueError: If key loading fails
        """
        try:
            key_path = self._validate_file_path(private_key_path)
            
            with open(key_path, 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password
                )
            
            self.public_key = self.private_key.public_key()
            
            if self.logger:
                self.logger.info(f"Loaded private key from: {key_path}")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error loading private key: {e}")
            raise ValueError(f"Failed to load private key: {e}")
    
    def load_public_key(self, public_key_path: str):
        """
        Load public key from file.
        
        Args:
            public_key_path (str): Path to public key file
            
        Raises:
            ValueError: If key loading fails
        """
        try:
            key_path = self._validate_file_path(public_key_path)
            
            with open(key_path, 'rb') as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read()
                )
            
            if self.logger:
                self.logger.info(f"Loaded public key from: {key_path}")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error loading public key: {e}")
            raise ValueError(f"Failed to load public key: {e}")
    
    def sign_file(self, file_path: str, signature_path: str = None) -> str:
        """
        Create a digital signature for a file.
        
        Args:
            file_path (str): Path to file to sign
            signature_path (str): Optional path for signature file
            
        Returns:
            str: Path to signature file
            
        Raises:
            ValueError: If private key not loaded or file operations fail
        """
        if not self.private_key:
            raise ValueError("Private key not loaded. Use load_private_key() first.")
        
        try:
            # Validate input file
            file_to_sign = self._validate_file_path(file_path)
            
            # Set default signature path
            if not signature_path:
                signature_path = str(file_to_sign) + ".sig"
            
            # Read file content
            with open(file_to_sign, 'rb') as f:
                file_content = f.read()
            
            # Create signature
            signature = self.private_key.sign(
                file_content,
                self.SIGNATURE_PADDING,
                self.SIGNATURE_ALGORITHM
            )
            
            # Write signature to file
            with open(signature_path, 'wb') as sig_file:
                sig_file.write(signature)
            
            if self.logger:
                self.logger.info(f"Signed file: {file_to_sign} -> {signature_path}")
            
            return signature_path
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error signing file: {e}")
            raise
    
    def verify_signature(self, file_path: str, signature_path: str) -> bool:
        """
        Verify a digital signature for a file.
        
        Args:
            file_path (str): Path to original file
            signature_path (str): Path to signature file
            
        Returns:
            bool: True if signature is valid, False otherwise
            
        Raises:
            ValueError: If public key not loaded or file operations fail
        """
        if not self.public_key:
            raise ValueError("Public key not loaded. Use load_public_key() first.")
        
        try:
            # Validate file paths
            file_to_verify = self._validate_file_path(file_path)
            sig_file = self._validate_file_path(signature_path)
            
            # Read file content and signature
            with open(file_to_verify, 'rb') as f:
                file_content = f.read()
            
            with open(sig_file, 'rb') as f:
                signature = f.read()
            
            # Verify signature
            try:
                self.public_key.verify(
                    signature,
                    file_content,
                    self.SIGNATURE_PADDING,
                    self.SIGNATURE_ALGORITHM
                )
                
                if self.logger:
                    self.logger.info(f"Signature verification successful: {file_to_verify}")
                
                return True
                
            except InvalidSignature:
                if self.logger:
                    self.logger.warning(f"Signature verification failed: {file_to_verify}")
                
                return False
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error verifying signature: {e}")
            raise


def main():
    """
    Main function to handle command-line interface.
    """
    parser = argparse.ArgumentParser(
        description='Digital signature tool for signing and verifying files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --generate-keys
  %(prog)s --generate-keys --private-key mykey.pem --public-key mykey.pub
  %(prog)s --sign --file document.txt --private-key private_key.pem
  %(prog)s --verify --file document.txt --signature document.txt.sig --public-key public_key.pem
        '''
    )
    
    # Main operation group
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        '--generate-keys', '-g',
        action='store_true',
        help='Generate RSA key pair'
    )
    operation_group.add_argument(
        '--sign', '-s',
        action='store_true',
        help='Sign a file'
    )
    operation_group.add_argument(
        '--verify', '-v',
        action='store_true',
        help='Verify a signature'
    )
    
    # File arguments
    parser.add_argument(
        '--file', '-f',
        type=str,
        help='File to sign or verify'
    )
    parser.add_argument(
        '--signature',
        type=str,
        help='Signature file for verification'
    )
    
    # Key arguments
    parser.add_argument(
        '--private-key',
        type=str,
        default='private_key.pem',
        help='Path to private key file (default: private_key.pem)'
    )
    parser.add_argument(
        '--public-key',
        type=str,
        default='public_key.pem',
        help='Path to public key file (default: public_key.pem)'
    )
    
    # Options
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Disable logging output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Digital Signature Tool v1.0.0'
    )
    
    try:
        args = parser.parse_args()
        
        # Create tool instance
        tool = DigitalSignatureTool(enable_logging=not args.quiet)
        
        if args.generate_keys:
            # Generate key pair
            private_path, public_path = tool.generate_key_pair(
                private_key_path=args.private_key,
                public_key_path=args.public_key
            )
            print("Generated key pair:")
            print(f"  Private key: {private_path}")
            print(f"  Public key: {public_path}")
            
        elif args.sign:
            # Sign file
            if not args.file:
                print("Error: --file is required for signing", file=sys.stderr)
                return 1
            
            tool.load_private_key(args.private_key)
            signature_path = tool.sign_file(args.file)
            print("File signed successfully:")
            print(f"  File: {args.file}")
            print(f"  Signature: {signature_path}")
            
        elif args.verify:
            # Verify signature
            if not args.file:
                print("Error: --file is required for verification", file=sys.stderr)
                return 1
            
            if not args.signature:
                # Try default signature path
                args.signature = args.file + ".sig"
            
            tool.load_public_key(args.public_key)
            is_valid = tool.verify_signature(args.file, args.signature)
            
            if is_valid:
                print("✓ Signature is VALID")
                return 0
            else:
                print("✗ Signature is INVALID")
                return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        return 1
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
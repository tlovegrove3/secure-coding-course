#!/usr/bin/env python3
"""
Program: SHA-256 Hash Generator
Author: Terry Lovegrove
Date: 2025-09-14
Description:
A secure application for generating SHA-256 hashes for strings and files.

"""

import hashlib
import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import Union


class SHA256Generator:
    """
    A secure SHA-256 hash generator class that follows industry best practices.
    """
    
    # Constants for security
    MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB limit
    CHUNK_SIZE = 8192  # 8KB chunks for memory efficiency
    MAX_STRING_LENGTH = 1024 * 1024  # 1MB string limit
    
    def __init__(self, enable_logging: bool = True):
        """
        Initialize the SHA256Generator with optional logging.
        
        Args:
            enable_logging (bool): Whether to enable logging
        """
        self.logger = self._setup_logging() if enable_logging else None
        self._last_operation_time = 0
        self._rate_limit_delay = 0.1  # 100ms between operations
    
    def _setup_logging(self) -> logging.Logger:
        """
        Set up secure logging configuration.
        
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger('sha256_generator')
        logger.setLevel(logging.INFO)
        
        # Create console handler with formatting
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _rate_limit(self):
        """
        Implement basic rate limiting to prevent abuse.
        """
        current_time = time.time()
        time_since_last = current_time - self._last_operation_time
        
        if time_since_last < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - time_since_last)
        
        self._last_operation_time = time.time()
    
    def _validate_string_input(self, input_string: str) -> bool:
        """
        Validate string input for security.
        
        Args:
            input_string (str): String to validate
            
        Returns:
            bool: True if valid, False otherwise
            
        Raises:
            ValueError: If string is invalid
        """
        if not isinstance(input_string, str):
            raise ValueError("Input must be a string")
        
        if len(input_string.encode('utf-8')) > self.MAX_STRING_LENGTH:
            raise ValueError(f"String too large. Maximum size: {self.MAX_STRING_LENGTH} bytes")
        
        return True
    
    def _validate_file_path(self, file_path: Union[str, Path]) -> Path:
        """
        Validate and sanitize file path for security.
        
        Args:
            file_path (Union[str, Path]): File path to validate
            
        Returns:
            Path: Validated and resolved path
            
        Raises:
            ValueError: If path is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file is not readable
        """
        try:
            path = Path(file_path).resolve()
        except Exception as e:
            raise ValueError(f"Invalid file path: {e}")
        
        # Security check: ensure path exists and is a file
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")
        
        # Security check: ensure file is readable
        if not os.access(path, os.R_OK):
            raise PermissionError(f"File is not readable: {path}")
        
        # Security check: file size limit
        file_size = path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(f"File too large. Maximum size: {self.MAX_FILE_SIZE} bytes")
        
        return path
    
    def hash_string(self, input_string: str) -> str:
        """
        Generate SHA-256 hash for a string.
        
        Args:
            input_string (str): String to hash
            
        Returns:
            str: Hexadecimal SHA-256 hash
            
        Raises:
            ValueError: If input is invalid
        """
        try:
            self._rate_limit()
            self._validate_string_input(input_string)
            
            # Create SHA-256 hash object
            sha256_hash = hashlib.sha256()
            
            # Update hash with UTF-8 encoded string
            sha256_hash.update(input_string.encode('utf-8'))
            
            # Get hexadecimal representation
            hex_hash = sha256_hash.hexdigest()
            
            if self.logger:
                self.logger.info(f"Generated hash for string (length: {len(input_string)})")
            
            return hex_hash
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error hashing string: {e}")
            raise
    
    def hash_file(self, file_path: Union[str, Path]) -> str:
        """
        Generate SHA-256 hash for a file using chunked reading.
        
        Args:
            file_path (Union[str, Path]): Path to file to hash
            
        Returns:
            str: Hexadecimal SHA-256 hash
            
        Raises:
            ValueError: If file path is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file is not readable
            IOError: If file reading fails
        """
        try:
            self._rate_limit()
            validated_path = self._validate_file_path(file_path)
            
            # Create SHA-256 hash object
            sha256_hash = hashlib.sha256()
            
            # Read file in chunks for memory efficiency
            with open(validated_path, 'rb') as file:
                while chunk := file.read(self.CHUNK_SIZE):
                    sha256_hash.update(chunk)
            
            # Get hexadecimal representation
            hex_hash = sha256_hash.hexdigest()
            
            if self.logger:
                file_size = validated_path.stat().st_size
                self.logger.info(f"Generated hash for file: {validated_path} (size: {file_size} bytes)")
            
            return hex_hash
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error hashing file {file_path}: {e}")
            raise


def main():
    """
    Main function to handle command-line interface.
    """
    parser = argparse.ArgumentParser(
        description='Generate SHA-256 hashes for strings and files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --string "Hello, World!"
  %(prog)s --file document.txt
  %(prog)s --file /path/to/large_file.zip
  %(prog)s --string "Secret message" --quiet
        '''
    )
    
    # Mutually exclusive group for string or file input
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--string', '-s',
        type=str,
        help='String to hash'
    )
    input_group.add_argument(
        '--file', '-f',
        type=str,
        help='File path to hash'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Disable logging output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SHA-256 Generator v1.0.0'
    )
    
    try:
        args = parser.parse_args()
        
        # Create SHA256Generator instance
        generator = SHA256Generator(enable_logging=not args.quiet)
        
        if args.string:
            # Hash string
            result = generator.hash_string(args.string)
            print(f"SHA-256 Hash: {result}")
            
        elif args.file:
            # Hash file
            result = generator.hash_file(args.file)
            print(f"SHA-256 Hash: {result}")
            print(f"File: {args.file}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        return 1
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

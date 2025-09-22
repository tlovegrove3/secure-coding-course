"""Command-line interface for the crypto integrity application."""

import argparse
import sys
from pathlib import Path
from .integrity import IntegrityService


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description='Crypto Integrity Tool')
    parser.add_argument('--encrypt', type=str, help='File to encrypt')
    parser.add_argument('--decrypt', type=str, help='File to decrypt')
    parser.add_argument('--message', type=str, help='Text message to process')
    
    args = parser.parse_args()
    
    service = IntegrityService()
    
    if args.message:
        # TODO: Process text message
        print(f"Processing message: {args.message}")
    elif args.encrypt:
        # TODO: Process file encryption
        print(f"Encrypting file: {args.encrypt}")
    elif args.decrypt:
        # TODO: Process file decryption  
        print(f"Decrypting file: {args.decrypt}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
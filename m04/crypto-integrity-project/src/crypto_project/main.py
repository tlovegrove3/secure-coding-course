"""Command-line interface for the crypto integrity application."""

import argparse
import sys
import json
from pathlib import Path
from .integrity import IntegrityService


def format_bytes_display(data: bytes, max_length: int = 32) -> str:
    """Format bytes for display in terminal."""
    hex_str = data.hex()
    if len(hex_str) > max_length:
        return f"{hex_str[:max_length]}..."
    return hex_str


def process_message(service: IntegrityService, message: str) -> None:
    """Process a text message through the complete crypto workflow."""
    print("🔒 === CRYPTOGRAPHIC MESSAGE PROCESSING ===")
    print(f"📝 Original message: {message}")
    print(f"📏 Message length: {len(message)} characters")
    
    # Convert to bytes
    message_bytes = message.encode('utf-8')
    
    # Secure the data
    print("\n🔐 --- SECURING MESSAGE ---")
    secured_package = service.secure_data(message_bytes)
    
    print("✅ Message secured successfully!")
    print(f"🔑 Encryption key: {format_bytes_display(secured_package['key'])}")
    print(f"🏷️  Integrity hash: {secured_package['hash'][:32]}...")
    print(f"🔒 Encrypted data: {format_bytes_display(secured_package['encrypted_data'])}")
    print(f"🎲 IV: {secured_package['iv'].hex()}")
    print(f"✓ Auth tag: {secured_package['auth_tag'].hex()}")
    
    # Verify and decrypt
    print("\n🔓 --- VERIFYING AND DECRYPTING ---")
    try:
        integrity_ok, decrypted_data = service.verify_and_decrypt(secured_package)
        decrypted_message = decrypted_data.decode('utf-8')
        
        print(f"🔍 Integrity verification: {'✅ PASSED' if integrity_ok else '❌ FAILED'}")
        print(f"📝 Decrypted message: {decrypted_message}")
        print(f"✅ Round-trip success: {message == decrypted_message}")
        
        if integrity_ok and message == decrypted_message:
            print("\n🎉 CIA TRIAD ACHIEVED:")
            print("   📊 Confidentiality: Message encrypted with AES-256")
            print("   🛡️  Integrity: SHA-256 hash verified no tampering")
            print("   🚀 Availability: Authorized decryption successful")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")


def encrypt_file(service: IntegrityService, file_path: str) -> None:
    """Encrypt a file and save the secured package."""
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"❌ ERROR: File '{file_path}' does not exist!")
        return
    
    print("🔒 === FILE ENCRYPTION ===")
    print(f"📁 Input file: {file_path}")
    print(f"📏 File size: {file_path.stat().st_size} bytes")
    
    # Read file content
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        print(f"✅ File loaded: {len(file_data)} bytes")
    except Exception as e:
        print(f"❌ ERROR reading file: {e}")
        return
    
    # Secure the file data
    print("\n🔐 --- ENCRYPTING FILE ---")
    secured_package = service.secure_data(file_data)
    
    # Save secured package
    output_file = file_path.with_suffix(file_path.suffix + '.secured')
    
    # Convert bytes to hex strings for JSON serialization
    json_package = {
        'original_filename': file_path.name,
        'encrypted_data': secured_package['encrypted_data'].hex(),
        'hash': secured_package['hash'],
        'key': secured_package['key'].hex(),
        'iv': secured_package['iv'].hex(),
        'auth_tag': secured_package['auth_tag'].hex()
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(json_package, f, indent=2)
        
        print("✅ File encrypted successfully!")
        print(f"📦 Secured package saved to: {output_file}")
        print(f"🔑 Encryption key: {format_bytes_display(secured_package['key'])}")
        print(f"🏷️  File hash: {secured_package['hash'][:32]}...")
        print("📊 Package components:")
        print(f"   - Original filename: {file_path.name}")
        print(f"   - Encrypted data: {len(secured_package['encrypted_data'])} bytes")
        print("   - Hash: SHA-256 (64 chars)")
        print("   - Key: AES-256 (32 bytes)")
        print("   - IV: 16 bytes")
        print("   - Auth tag: 16 bytes")
        
    except Exception as e:
        print(f"❌ ERROR saving secured package: {e}")


def decrypt_file(service: IntegrityService, secured_file_path: str) -> None:
    """Decrypt a secured file package."""
    secured_file_path = Path(secured_file_path)
    
    if not secured_file_path.exists():
        print(f"❌ ERROR: Secured file '{secured_file_path}' does not exist!")
        return
    
    print("🔓 === FILE DECRYPTION ===")
    print(f"📦 Secured package: {secured_file_path}")
    
    # Load secured package
    try:
        with open(secured_file_path, 'r') as f:
            json_package = json.load(f)
        print("✅ Secured package loaded")
    except Exception as e:
        print(f"❌ ERROR loading secured package: {e}")
        return
    
    # Convert hex strings back to bytes
    try:
        secured_package = {
            'encrypted_data': bytes.fromhex(json_package['encrypted_data']),
            'hash': json_package['hash'],
            'key': bytes.fromhex(json_package['key']),
            'iv': bytes.fromhex(json_package['iv']),
            'auth_tag': bytes.fromhex(json_package['auth_tag'])
        }
        original_filename = json_package['original_filename']
        print(f"📁 Original filename: {original_filename}")
    except Exception as e:
        print(f"❌ ERROR parsing secured package: {e}")
        return
    
    # Verify and decrypt
    print("\n🔍 --- VERIFYING AND DECRYPTING ---")
    try:
        integrity_ok, decrypted_data = service.verify_and_decrypt(secured_package)
        
        print(f"🔍 Integrity verification: {'✅ PASSED' if integrity_ok else '❌ FAILED'}")
        print(f"📏 Decrypted size: {len(decrypted_data)} bytes")
        
        if integrity_ok:
            # Save decrypted file
            output_file = secured_file_path.with_name(f"decrypted_{original_filename}")
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            print("✅ File decrypted successfully!")
            print(f"💾 Decrypted file saved as: {output_file}")
            print("\n🎉 SECURITY VERIFICATION COMPLETE:")
            print("   📊 Confidentiality: File was encrypted and now decrypted")
            print("   🛡️  Integrity: Hash verification confirms no tampering")
            print("   🚀 Availability: File successfully recovered")
        else:
            print("⚠️  WARNING: Integrity check failed!")
            print("   File may have been tampered with or corrupted.")
            print("   Decrypted data should not be trusted.")
            
    except Exception as e:
        print(f"❌ DECRYPTION FAILED: {e}")
        print("   This could indicate:")
        print("   - Wrong key or corrupted package")
        print("   - File has been tampered with")
        print("   - Package format is invalid")


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description='Crypto Integrity Tool - Secure your data with AES-256 + SHA-256',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --message "Secret launch codes: Alpha-7-Charlie"
  %(prog)s --encrypt myfile.txt
  %(prog)s --decrypt myfile.txt.secured
        """
    )
    
    # Create mutually exclusive group - only one action at a time
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--message', type=str, 
                             help='Encrypt and decrypt a text message')
    action_group.add_argument('--encrypt', type=str, metavar='FILE',
                             help='Encrypt a file')
    action_group.add_argument('--decrypt', type=str, metavar='SECURED_FILE',
                             help='Decrypt a secured file (.secured)')
    
    args = parser.parse_args()
    
    # Initialize the crypto service
    service = IntegrityService()
    
    try:
        if args.message:
            process_message(service, args.message)
        elif args.encrypt:
            encrypt_file(service, args.encrypt)
        elif args.decrypt:
            decrypt_file(service, args.decrypt)
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
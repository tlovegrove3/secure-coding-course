#!/usr/bin/env python3
"""
Secret Scanner - A CLI tool to detect hardcoded secrets in files
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("secret_scanner.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class SecretPattern:
    """
    Represents a secret pattern with its regex and description
    """

    def __init__(self, name: str, pattern: str, description: str):
        self.name = name
        self.pattern = re.compile(pattern)
        self.description = description


# Define secret patterns based on the GitHub repository
SECRET_PATTERNS = [
    SecretPattern(
        "GitHub Personal Access Token (Classic)",
        r"ghp_[a-zA-Z0-9]{36}",
        "GitHub personal access token",
    ),
    SecretPattern(
        "GitHub Fine-Grained PAT",
        r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "GitHub fine-grained personal access token",
    ),
    SecretPattern(
        "GitHub OAuth Token", r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth access token"
    ),
    SecretPattern(
        "GitHub User Token", r"ghu_[a-zA-Z0-9]{36}", "GitHub user-to-server token"
    ),
    SecretPattern(
        "GitHub Server Token", r"ghs_[a-zA-Z0-9]{36}", "GitHub server-to-server token"
    ),
    SecretPattern(
        "GitHub Refresh Token", r"ghr_[a-zA-Z0-9]{36}", "GitHub refresh token"
    ),
    SecretPattern(
        "AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "AWS access key identifier"
    ),
    SecretPattern(
        "Slack Bot Token",
        r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        "Slack bot token",
    ),
    SecretPattern(
        "Slack User Token",
        r"xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        "Slack user token",
    ),
    SecretPattern(
        "Slack Webhook",
        r"T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "Slack webhook URL",
    ),
    SecretPattern(
        "Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24}", "Stripe live secret key"
    ),
    SecretPattern("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    SecretPattern(
        "OpenAI API Key", r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "OpenAI API key"
    ),
    SecretPattern(
        "OpenAI Project API Key",
        r"sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
        "OpenAI project API key",
    ),
    SecretPattern(
        "Generic API Key Pattern",
        r'(?i)api[_-]?key[_-]?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]+)["\']?',
        "Generic API key assignment",
    ),
    SecretPattern(
        "Generic Password Pattern",
        r'(?i)password[_-]?\s*[=:]\s*["\']?([a-zA-Z0-9_\-@!#$%^&*()+={}\[\]:;<>,.?/~`|\\]+)["\']?',
        "Generic password assignment",
    ),
    SecretPattern(
        "Generic Token Pattern",
        r'(?i)token[_-]?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]+)["\']?',
        "Generic token assignment",
    ),
    SecretPattern(
        "Private Key Header",
        r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----",
        "Private key file header",
    ),
]

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".pyo",
    ".class",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".mkv",
    ".db",
    ".sqlite",
    ".sqlite3",
}


def is_binary_file(filepath: Path) -> bool:
    """
    Check if a file is binary by extension or by checking for null bytes

    Think of this like checking if a book is in a language you can read:
    - First check the cover (extension)
    - Then peek at a few pages (read some bytes)
    """
    # Check extension first (fast)
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        logger.debug(f"Skipping binary file by extension: {filepath}")
        return True

    # Check content for null bytes (slower but more accurate)
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)  # Read first 1KB
            if b"\x00" in chunk:  # Null byte indicates binary
                logger.debug(f"Skipping binary file by content: {filepath}")
                return True
    except Exception as e:
        logger.warning(f"Could not read file {filepath}: {e}")
        return True

    return False


def scan_file(filepath: Path) -> List[Dict]:
    """
    Scan a single file for secrets

    Returns a list of findings, each containing:
    - filename, line_number, line_content, pattern_name, matched_string
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                # Check each pattern against this line
                for pattern in SECRET_PATTERNS:
                    matches = pattern.pattern.finditer(line)
                    for match in matches:
                        finding = {
                            "filename": str(filepath),
                            "line_number": line_num,
                            "line_content": line.strip(),
                            "pattern_name": pattern.name,
                            "pattern_description": pattern.description,
                            "matched_string": match.group(0),
                        }
                        findings.append(finding)
                        logger.info(f"Found {pattern.name} in {filepath}:{line_num}")
    except Exception as e:
        logger.error(f"Error scanning file {filepath}: {e}")

    return findings


def scan_directory(directory: Path) -> List[Dict]:
    """
    Scan all files in the immediate directory (non-recursive)

    Like checking every book on a single shelf, not the entire library
    """
    all_findings = []
    files_scanned = 0
    files_skipped = 0

    logger.info(f"Starting scan of directory: {directory}")

    try:
        # List all items in directory
        for item in directory.iterdir():
            # Only process files, not subdirectories
            if item.is_file():
                # Skip binary files
                if is_binary_file(item):
                    files_skipped += 1
                    continue

                logger.debug(f"Scanning file: {item}")
                findings = scan_file(item)
                all_findings.extend(findings)
                files_scanned += 1
            else:
                logger.debug(f"Skipping directory: {item}")

    except Exception as e:
        logger.error(f"Error accessing directory {directory}: {e}")
        sys.exit(1)

    logger.info(
        f"Scan complete: {files_scanned} files scanned, {files_skipped} files skipped"
    )
    return all_findings


def print_report(findings: List[Dict]):
    """
    Print a formatted report of all findings

    Think of this as creating a table of contents for all the secrets found
    """
    if not findings:
        print("\n✅ No secrets detected!")
        logger.info("No secrets found")
        return

    print(f"\n⚠️  Found {len(findings)} potential secret(s):\n")
    print("=" * 80)

    for i, finding in enumerate(findings, start=1):
        print(f"\nFinding #{i}")
        print(f"  Type: {finding['pattern_name']}")
        print(f"  Description: {finding['pattern_description']}")
        print(f"  File: {finding['filename']}")
        print(f"  Line: {finding['line_number']}")
        print(f"  Matched: {finding['matched_string']}")
        print(f"  Context: {finding['line_content'][:100]}...")
        print("-" * 80)

    logger.info(f"Report generated with {len(findings)} findings")


def main():
    """
    Main entry point for the CLI tool

    argparse is like a GPS for your program - it helps users navigate
    by telling them what paths (arguments) they can take
    """
    parser = argparse.ArgumentParser(
        description="Scan files for hardcoded secrets like API keys,"
        " tokens, and passwords",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        %(prog)s /path/to/project
        %(prog)s ./src --verbose
        %(prog)s myfile.py
        """,
    )

    parser.add_argument(
        "path",
        type=str,
        help="Path to file or directory to scan (directory scans are non-recursive)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )

    args = parser.parse_args()

    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")

    # Convert path string to Path object
    target_path = Path(args.path)

    # Validate path exists
    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        sys.exit(1)

    # Determine if path is file or directory
    if target_path.is_file():
        logger.info(f"Scanning single file: {target_path}")
        if is_binary_file(target_path):
            logger.warning("Target is a binary file, skipping")
            sys.exit(0)
        findings = scan_file(target_path)
    elif target_path.is_directory():
        logger.info(f"Scanning directory: {target_path}")
        findings = scan_directory(target_path)
    else:
        logger.error(f"Path is neither a file nor directory: {target_path}")
        sys.exit(1)

    # Print the report
    print_report(findings)

    # Exit with appropriate code
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()

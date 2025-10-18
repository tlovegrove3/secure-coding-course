# Secret Scanner CLI Tool

A Python CLI tool that scans files for hardcoded secrets like API keys, passwords, tokens, and private keys using regex patterns.

## Quick Start

```bash
# Scan a directory
python secret_scanner.py /path/to/project

# Scan a single file
python secret_scanner.py myfile.py

# Verbose output
python secret_scanner.py ./src --verbose
```

**Requirements**: Python 3.6+ (no external dependencies)

## Detection Logic

### How It Works

The scanner uses **regex patterns** to identify secrets based on their format. It works like a metal detector scanning through your code:

1. **File Discovery** - Lists all files in the target directory
2. **Binary Check** - Skips images, executables, etc. (via extension or null byte detection)
3. **Line-by-Line Scan** - Reads each text file line by line
4. **Pattern Matching** - Tests each line against 18 secret patterns
5. **Report Generation** - Outputs findings with file, line number, and context

### Detected Secrets

The tool detects these secret types based on official format specifications:

- **GitHub tokens** (`ghp_`, `gho_`, `ghs_`, etc.) - Various GitHub access tokens
- **AWS keys** (`AKIA...`) - AWS access key identifiers  
- **Slack tokens** (`xoxb-`, `xoxp-`) - Bot and user tokens
- **Stripe keys** (`sk_live_...`) - Live secret keys
- **Google API** (`AIza...`) - Google Cloud API keys
- **OpenAI keys** (`sk-...T3BlbkFJ...`) - OpenAI API keys
- **Generic patterns** - `api_key=`, `password=`, `token=` assignments
- **Private keys** (`-----BEGIN PRIVATE KEY-----`) - RSA/SSH keys

### Why These Patterns?

Each pattern matches the **exact format** services use:

- Specific prefixes (e.g., `AKIA` for AWS, `ghp_` for GitHub)
- Required lengths (e.g., 36 characters for GitHub tokens)
- Character sets (alphanumeric, hyphens, underscores)

This reduces false positives while catching real secrets.

## Output Example

```bsh
⚠️  Found 2 potential secret(s):

Finding #1
  Type: GitHub Personal Access Token
  File: config.py
  Line: 15
  Matched: ghp_abc123xyz789...
  Context: GITHUB_TOKEN = "ghp_abc123xyz789..."

Finding #2
  Type: AWS Access Key ID
  File: settings.py
  Line: 23
  Matched: AKIAIOSFODNN7EXAMPLE
  Context: aws_access_key = "AKIAIOSFODNN7EXAMPLE"
```

All activity is also logged to `secret_scanner.log`.

## Usage

```py
python secret_scanner.py <path> [options]

Arguments:
  path                 File or directory to scan (non-recursive)

Options:
  -h, --help          Show help message
  -v, --verbose       Enable debug logging
```

## Limitations

- **Non-recursive** - Only scans immediate directory files
- **Regex-based** - May produce false positives
- **No validation** - Doesn't check if secrets are active
- **Text files only** - Skips binary and encoded files

## Best Practices

✅ Run before every commit  
✅ Review all findings manually  
✅ Use environment variables instead of hardcoding secrets  
✅ Add to CI/CD pipeline  

❌ Don't rely on this tool alone  
❌ Don't commit secrets to version control  

---

**Remember**: The best secret is one that's never hardcoded. Use environment variables, secret managers (AWS Secrets Manager, HashiCorp Vault), or gitignored config files instead.

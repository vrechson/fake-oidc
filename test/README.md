# Test Directory

This directory contains test scripts and utilities for the fake-oidc server.

**Note**: This directory is git-ignored and will not be committed to the repository.

## Scripts

### `oidc_login_generator.py`

A Python script that processes the `config.json` file and generates OIDC login URLs with configurable parameters.

#### Features

- **Config Processing**: Reads and parses the fake-oidc configuration file
- **PKCE Support**: Automatically detects PKCE requirements from config or allows manual override
- **Flexible Parameters**: Configurable redirect URI, scopes, and state
- **Token Exchange**: Generates curl commands for token exchange
- **Verbose Output**: Detailed information about the generated URLs and parameters

#### Usage

```bash
# Basic usage (uses default redirect URI)
python oidc_login_generator.py

# Custom redirect URI
python oidc_login_generator.py --redirect-uri "http://localhost:8080/callback"

# Force PKCE usage
python oidc_login_generator.py --pkce

# Custom scopes and state
python oidc_login_generator.py --scopes "openid profile email" --state "my-test-state"

# Verbose output
python oidc_login_generator.py --verbose

# Custom config file
python oidc_login_generator.py --config ../my-config.json
```

#### Command Line Options

- `--config, -c`: Path to configuration file (default: ../config.json)
- `--redirect-uri, -r`: Redirect URI for OIDC flow (default: http://localhost:3000/callback)
- `--scopes, -s`: OIDC scopes to request (default: openid profile email)
- `--state`: State parameter for CSRF protection (auto-generated if not provided)
- `--pkce`: Force PKCE usage (overrides config setting)
- `--no-pkce`: Disable PKCE usage (overrides config setting)
- `--verbose, -v`: Show detailed information

#### Example Output

```
🔐 OIDC Login URL Generator
==================================================

📋 Configuration:
  Config file: ../config.json
  Client ID: dev-client
  Issuer URL: https://gauss.lemonslab.me:7835
  Redirect URI: http://localhost:3000/callback
  Scopes: openid profile email
  State: abc123def456
  PKCE Enabled: true
  Code Challenge: 4NdeytoZGXAuzHwfh6f3jdNjryEVFcmG1T5b62y8eM
  Code Challenge Method: S256

🌐 Login URL:
https://gauss.lemonslab.me:7835/authorize?client_id=dev-client&redirect_uri=http%3A//localhost%3A3000/callback&response_type=code&scope=openid%20profile%20email&state=abc123def456&code_challenge=4NdeytoZGXAuzHwfh6f3jdNjryEVFcmG1T5b62y8eM&code_challenge_method=S256

🔑 PKCE Parameters:
  Code Verifier: w9uu3LWib4jX4mYYiRwzg0SWzslROyaWxGNzv9i20I
  Code Challenge: 4NdeytoZGXAuzHwfh6f3jdNjryEVFcmG1T5b62y8eM

📝 Token Exchange Command:
(Replace AUTHORIZATION_CODE with the code from the callback)

curl -X POST \
  "https://gauss.lemonslab.me:7835/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=w9uu3LWib4jX4mYYiRwzg0SWzslROyaWxGNzv9i20I" \
  -u "dev-client:secure-secret"

💡 Usage Instructions:
1. Open the login URL in your browser
2. Complete the login form
3. Copy the authorization code from the callback URL
4. Replace 'AUTHORIZATION_CODE' in the curl command above
5. Run the curl command to get tokens
```

## Requirements

- Python 3.7+
- No external dependencies (uses only standard library)

## Configuration

The script automatically reads the fake-oidc configuration file and extracts:
- Client ID and secret
- Server host, port, and TLS settings
- PKCE requirements
- Issuer URL (auto-generated if not specified)

Make sure you have a valid `config.json` file in the parent directory before running the script.

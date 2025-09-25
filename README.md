# fake-oidc

A simple, configurable OpenID Connect provider intended for use in local development and automated tests.

## Features
 
- **In-memory storage**: Everything is stored in-memory, therefore data will not be persisted between restarts
- **Full OIDC compliance**: Implements all standard OpenID Connect endpoints
- **Rich user claims**: Supports nested fields and custom claims in user profiles
- **Configurable client**: Customizable client credentials and redirect URIs
- **TLS/HTTPS support**: Optional TLS encryption with custom certificates
- **PKCE support**: Configurable Proof Key for Code Exchange (PKCE) enforcement
- **Flexible configuration**: JSON configuration file with command-line overrides
- **Development-friendly**: Accepts any username for testing, supports automated testing

### Supported OIDC Endpoints

- `/.well-known/openid-configuration` - Discovery endpoint
- `/authorize` - Authorization endpoint
- `/oauth/token` - Token endpoint
- `/userinfo` - UserInfo endpoint
- `/oauth/introspect` - Token introspection endpoint
- `/revoke` - Token revocation endpoint
- `/end_session` - End session endpoint
- `/keys` - JWKS endpoint
- `/health` - Health check endpoint

### Supported Grant Types

- `authorization_code` - Standard OAuth2 authorization code flow
- `refresh_token` - Token refresh flow

## Configuration

### Command Line Options

```bash
./fake-oidc [options]

Options:
  -config string
        Path to configuration file (JSON)
  -host string
        Host to bind to (overrides config and env)
  -port string
        Port to listen on (overrides config and env)
  -verbose
        Enable verbose logging
```

### Configuration File

The server can be configured using a JSON configuration file. See `config.json.sample` for a complete example.

**Note**: Configuration files are git-ignored to prevent committing sensitive data. Copy the sample files to create your own configuration:

```bash
# Copy sample configuration files
cp config.json.sample config.json
cp config-no-tls.json.sample config-no-tls.json
cp test-config.json.sample test-config.json
```

Key configuration sections:
- **Server**: Host, port, and TLS settings
- **Client**: Client ID, secret, and redirect URIs
- **User Data**: Rich user profile with nested fields and custom claims
- **Features**: OIDC capabilities and supported scopes/claims

#### Server vs Issuer Configuration

**`server.host`** - Controls which network interface the server binds to:
- `""` (empty) - Bind to all interfaces (0.0.0.0)
- `"localhost"` - Bind only to localhost/127.0.0.1
- `"192.168.1.100"` - Bind to specific IP address

**`issuer.url`** - The public URL that clients will use to discover your OIDC server:
- `""` (empty) - Auto-generated from server.host, port, and TLS settings
- `"https://oidc.example.com"` - Custom public URL (for production)
- `"http://localhost:7835"` - Explicit localhost URL

**Examples:**

```json
// Local development - bind to all interfaces, auto-generate issuer URL
{
  "server": { "host": "", "port": "7835" },
  "issuer": { "url": "" }
}

// Local development - bind to localhost only
{
  "server": { "host": "localhost", "port": "7835" },
  "issuer": { "url": "" }
}

// Production - bind to specific IP, custom issuer URL
{
  "server": { "host": "192.168.1.100", "port": "443" },
  "issuer": { "url": "https://oidc.example.com" }
}
```

#### Example Configuration

```json
{
  "server": {
    "host": "",
    "port": "7835",
    "tls": {
      "enabled": true,
      "cert_file": "certs/server.crt",
      "key_file": "certs/server.key"
    }
  },
  "client": {
    "id": "dev-client",
    "secret": "secure-secret",
    "redirect_uris": ["**"]
  },
  "user_data": {
    "default_user": {
      "name": "Test User",
      "email": "testuser@example.com",
      "profile": {
        "first_name": "Test",
        "last_name": "User"
      },
      "custom_claims": {
        "department": "Engineering",
        "role": "Developer"
      }
    }
  }
}
```

### TLS Support

The server supports TLS/HTTPS with custom certificates:

```bash
# Generate self-signed certificates
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"

# Run with TLS
./fake-oidc --config config.json --port 8443
```

### PKCE Support

The server supports configurable PKCE (Proof Key for Code Exchange) enforcement:

```json
{
  "features": {
    "require_pkce": true
  }
}
```

**PKCE Configuration:**
- `"require_pkce": false` (default) - PKCE is optional, clients can use it or not
- `"require_pkce": true` - PKCE is mandatory, all authorization requests must include `code_challenge` and `code_challenge_method`

**Supported PKCE Methods:**
- `S256` - SHA256 hash of code verifier (recommended)
- `plain` - Plain text code verifier (less secure)

**Example PKCE Flow:**
```bash
# 1. Generate code verifier and challenge
code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
code_challenge=$(echo -n "$code_verifier" | openssl dgst -binary -sha256 | openssl base64 | tr -d "=+/" | cut -c1-43)

# 2. Start authorization with PKCE
curl "https://gauss.lemonslab.me:7835/authorize?client_id=dev-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=$code_challenge&code_challenge_method=S256&state=test123"

# 3. Exchange code for tokens with code verifier
curl -X POST "https://gauss.lemonslab.me:7835/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=$code_verifier" \
  -u "dev-client:secure-secret"
```

**Note**: The `certs/` directory and certificate files are automatically ignored by git to prevent accidentally committing private keys to version control.

### Environment Variables

By default fake-oidc starts on port 7835.
This can be overriden by setting the environment variable `FAKE_OIDC_HTTP_PORT`.

Example: `FAKE_OIDC_HTTP_PORT=1234 fake-oidc`.

## Usage Examples

### Basic Usage

```bash
# Run with default configuration
./fake-oidc

# Run with custom configuration
./fake-oidc --config config.json

# Run on specific port
./fake-oidc --port 8080

# Run with TLS
./fake-oidc --config config.json --port 8443
```

### Testing OIDC Flow

1. **Start the server**:
   ```bash
   ./fake-oidc --config config.json --port 7835
   ```

2. **Get discovery information**:
   ```bash
   curl http://localhost:7835/.well-known/openid-configuration
   ```

3. **Test authorization flow**:
   ```bash
   # Open in browser or use curl
   curl "http://localhost:7835/authorize?response_type=code&client_id=dev-client&redirect_uri=http://localhost:8080/callback&scope=openid profile email&state=test"
   ```

4. **Login with any username**:
   - Visit the login page and enter any username
   - For automated testing, add `?username=testuser` to the login URL

### Configuration Examples

```bash
# Use custom client credentials
./fake-oidc --config my-config.json

# Override port from config
./fake-oidc --config config.json --port 9000

# Enable verbose logging
./fake-oidc --config config.json --verbose
```

## Login

On the login page, any username can be entered and will be accepted.

For automated tests, the query parameter `username=MY_USERNAME_HERE` can be added to the login
route to bypass the login form and callback to the resource server immediately.

Example: `http://localhost:7835/login?username=testuser&authRequestID=12345`

## Troubleshooting

### Common Issues

1. **Port already in use**: If you get "bind: address already in use", try a different port:
   ```bash
   ./fake-oidc --port 8080
   ```

2. **TLS certificate errors**: Make sure certificates are generated and paths are correct:
   ```bash
   ls -la certs/
   ```
   
   If you get "TLS handshake error: unknown certificate", the certificate doesn't match your domain:
   ```bash
   # Generate certificate for your domain
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=yourdomain.com" -addext "subjectAltName=DNS:yourdomain.com,DNS:*.yourdomain.com,IP:YOUR_IP"
   ```

3. **Configuration not loading**: Check that the config file exists and is valid JSON:
   ```bash
   ./fake-oidc --config config.json --verbose
   ```
   
   If you get "config file not found", make sure you've copied the sample files:
   ```bash
   cp config.json.sample config.json
   ```

### Known Issues

- **Issuer URL**: The issuer URL in discovery responses may not always reflect the actual server port due to internal configuration handling. This doesn't affect functionality but may cause confusion in discovery responses.

## Disclaimer

This is a development/testing tool and should not be used in production environments. There are probably many issues with this implementation, but it seems to work okay for basic testing.

Please report any issues.


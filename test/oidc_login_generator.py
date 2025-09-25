#!/usr/bin/env python3
"""
OIDC Login URL Generator

This script processes the config.json file and generates OIDC login URLs
with configurable redirect_uri parameter.

Usage:
    python oidc_login_generator.py [--config CONFIG_FILE] [--redirect-uri REDIRECT_URI] [--pkce]

Examples:
    python oidc_login_generator.py
    python oidc_login_generator.py --redirect-uri "http://localhost:3000/callback"
    python oidc_login_generator.py --config ../config.json --pkce
"""

import json
import argparse
import urllib.parse
import hashlib
import base64
import secrets
import sys
import os
from typing import Dict, Any, Optional


class OIDCLoginGenerator:
    def __init__(self, config_path: str = "config.json"):
        """Initialize the OIDC login generator with configuration."""
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file '{self.config_path}' not found.")
            print("Make sure you have a config.json file in the parent directory.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in configuration file: {e}")
            sys.exit(1)
    
    def _generate_pkce_params(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        # Generate code verifier (43-128 characters, URL-safe)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of code verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def _get_issuer_url(self) -> str:
        """Get the issuer URL from configuration."""
        issuer_url = self.config.get('issuer', {}).get('url', '')
        if not issuer_url:
            # Auto-generate from server config
            server_config = self.config.get('server', {})
            host = server_config.get('host', 'localhost')
            port = server_config.get('port', '7835')
            tls_enabled = server_config.get('tls', {}).get('enabled', False)
            
            protocol = 'https' if tls_enabled else 'http'
            if host == '':
                host = 'localhost'
            
            issuer_url = f"{protocol}://{host}:{port}"
        
        return issuer_url
    
    def generate_login_url(self, 
                          redirect_uri: str = "http://localhost:3000/callback",
                          scopes: list = None,
                          state: str = None,
                          use_pkce: bool = None) -> Dict[str, str]:
        """
        Generate OIDC login URL with optional PKCE support.
        
        Args:
            redirect_uri: The redirect URI for the OIDC flow
            scopes: List of OIDC scopes to request
            state: State parameter for CSRF protection
            use_pkce: Whether to use PKCE (auto-detected from config if None)
        
        Returns:
            Dictionary containing login URL and optional PKCE parameters
        """
        if scopes is None:
            scopes = ['openid', 'profile', 'email']
        
        if state is None:
            # Generate a simple alphanumeric state to avoid URL encoding issues
            state = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))
        
        # Get configuration values
        client_id = self.config.get('client', {}).get('id', 'dev-client')
        issuer_url = self._get_issuer_url()
        require_pkce = self.config.get('features', {}).get('require_pkce', False)
        
        # Determine if PKCE should be used
        if use_pkce is None:
            use_pkce = require_pkce
        
        # Build base parameters
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state
        }
        
        result = {
            'login_url': '',
            'state': state,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'issuer_url': issuer_url
        }
        
        # Add PKCE parameters if required or requested
        if use_pkce:
            code_verifier, code_challenge = self._generate_pkce_params()
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = 'S256'
            
            result['code_verifier'] = code_verifier
            result['code_challenge'] = code_challenge
            result['code_challenge_method'] = 'S256'
            result['pkce_enabled'] = True
        else:
            result['pkce_enabled'] = False
        
        # Build the authorization URL
        auth_url = f"{issuer_url}/authorize"
        query_string = urllib.parse.urlencode(params)
        result['login_url'] = f"{auth_url}?{query_string}"
        
        return result
    
    def generate_token_exchange_command(self, 
                                      auth_code: str,
                                      redirect_uri: str = "http://localhost:3000/callback",
                                      code_verifier: str = None) -> str:
        """
        Generate curl command for token exchange.
        
        Args:
            auth_code: The authorization code from the callback
            redirect_uri: The redirect URI used in the authorization request
            code_verifier: The PKCE code verifier (if PKCE was used)
        
        Returns:
            Curl command string for token exchange
        """
        client_id = self.config.get('client', {}).get('id', 'dev-client')
        client_secret = self.config.get('client', {}).get('secret', 'secure-secret')
        issuer_url = self._get_issuer_url()
        
        # Build token exchange command
        cmd_parts = [
            'curl -X POST',
            f'"{issuer_url}/oauth/token"',
            '-H "Content-Type: application/x-www-form-urlencoded"',
            f'-d "grant_type=authorization_code"',
            f'-d "code={auth_code}"',
            f'-d "redirect_uri={redirect_uri}"'
        ]
        
        # Add PKCE code verifier if provided
        if code_verifier:
            cmd_parts.append(f'-d "code_verifier={code_verifier}"')
        
        # Add client authentication
        cmd_parts.append(f'-u "{client_id}:{client_secret}"')
        
        return ' \\\n  '.join(cmd_parts)


def main():
    """Main function to handle command line arguments and generate login URLs."""
    parser = argparse.ArgumentParser(
        description='Generate OIDC login URLs from configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --redirect-uri "http://localhost:3000/callback"
  %(prog)s --config ../config.json --pkce
  %(prog)s --scopes "openid profile email" --state "my-state"
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    parser.add_argument(
        '--redirect-uri', '-r',
        default='http://localhost:3000/callback',
        help='Redirect URI for OIDC flow (default: http://localhost:3000/callback)'
    )
    
    parser.add_argument(
        '--scopes', '-s',
        nargs='+',
        default=['openid', 'profile', 'email'],
        help='OIDC scopes to request (default: openid profile email)'
    )
    
    parser.add_argument(
        '--state',
        help='State parameter for CSRF protection (auto-generated if not provided)'
    )
    
    parser.add_argument(
        '--pkce',
        action='store_true',
        help='Force PKCE usage (overrides config setting)'
    )
    
    parser.add_argument(
        '--no-pkce',
        action='store_true',
        help='Disable PKCE usage (overrides config setting)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information'
    )
    
    args = parser.parse_args()
    
    # Initialize generator
    try:
        generator = OIDCLoginGenerator(args.config)
    except SystemExit:
        return 1
    
    # Determine PKCE usage
    use_pkce = None
    if args.pkce:
        use_pkce = True
    elif args.no_pkce:
        use_pkce = False
    
    # Generate login URL
    result = generator.generate_login_url(
        redirect_uri=args.redirect_uri,
        scopes=args.scopes,
        state=args.state,
        use_pkce=use_pkce
    )
    
    # Display results
    print("🔐 OIDC Login URL Generator")
    print("=" * 50)
    print()
    
    if args.verbose:
        print("📋 Configuration:")
        print(f"  Config file: {args.config}")
        print(f"  Client ID: {result['client_id']}")
        print(f"  Issuer URL: {result['issuer_url']}")
        print(f"  Redirect URI: {result['redirect_uri']}")
        print(f"  Scopes: {' '.join(args.scopes)}")
        print(f"  State: {result['state']}")
        print(f"  PKCE Enabled: {result['pkce_enabled']}")
        if result['pkce_enabled']:
            print(f"  Code Challenge: {result['code_challenge']}")
            print(f"  Code Challenge Method: {result['code_challenge_method']}")
        print()
    
    print("🌐 Login URL:")
    print(result['login_url'])
    print()
    
    if result['pkce_enabled']:
        print("🔑 PKCE Parameters:")
        print(f"  Code Verifier: {result['code_verifier']}")
        print(f"  Code Challenge: {result['code_challenge']}")
        print()
    
    print("📝 Token Exchange Command:")
    print("(Replace AUTHORIZATION_CODE with the code from the callback)")
    print()
    token_cmd = generator.generate_token_exchange_command(
        auth_code="AUTHORIZATION_CODE",
        redirect_uri=args.redirect_uri,
        code_verifier=result.get('code_verifier')
    )
    print(token_cmd)
    print()
    
    print("💡 Usage Instructions:")
    print("1. Open the login URL in your browser")
    print("2. Complete the login form")
    print("3. Copy the authorization code from the callback URL")
    print("4. Replace 'AUTHORIZATION_CODE' in the curl command above")
    print("5. Run the curl command to get tokens")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

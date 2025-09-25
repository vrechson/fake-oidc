#!/usr/bin/env python3
"""
Example usage of the OIDC Login Generator

This script demonstrates how to use the OIDCLoginGenerator class
programmatically to generate login URLs and token exchange commands.
"""

import sys
import os

# Add the current directory to the path so we can import the generator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oidc_login_generator import OIDCLoginGenerator


def main():
    """Demonstrate different ways to use the OIDC Login Generator."""
    
    print("🔐 OIDC Login Generator - Example Usage")
    print("=" * 50)
    print()
    
    # Example 1: Basic usage with default config
    print("📋 Example 1: Basic Usage")
    print("-" * 30)
    
    try:
        generator = OIDCLoginGenerator("config.json")
        
        # Generate a basic login URL
        result = generator.generate_login_url()
        
        print(f"Login URL: {result['login_url']}")
        print(f"State: {result['state']}")
        print(f"PKCE Enabled: {result['pkce_enabled']}")
        print()
        
    except Exception as e:
        print(f"Error: {e}")
        print()
    
    # Example 2: Custom redirect URI
    print("📋 Example 2: Custom Redirect URI")
    print("-" * 30)
    
    try:
        generator = OIDCLoginGenerator("config.json")
        
        result = generator.generate_login_url(
            redirect_uri="http://localhost:8080/my-app/callback",
            scopes=["openid", "profile", "email", "phone"],
            state="custom-state-123"
        )
        
        print(f"Login URL: {result['login_url']}")
        print(f"Redirect URI: {result['redirect_uri']}")
        print(f"Scopes: openid profile email phone")
        print(f"State: {result['state']}")
        print()
        
    except Exception as e:
        print(f"Error: {e}")
        print()
    
    # Example 3: Force PKCE usage
    print("📋 Example 3: Force PKCE Usage")
    print("-" * 30)
    
    try:
        generator = OIDCLoginGenerator("config.json")
        
        result = generator.generate_login_url(
            redirect_uri="http://localhost:3000/callback",
            use_pkce=True
        )
        
        print(f"Login URL: {result['login_url']}")
        print(f"PKCE Enabled: {result['pkce_enabled']}")
        if result['pkce_enabled']:
            print(f"Code Verifier: {result['code_verifier']}")
            print(f"Code Challenge: {result['code_challenge']}")
        print()
        
    except Exception as e:
        print(f"Error: {e}")
        print()
    
    # Example 4: Generate token exchange command
    print("📋 Example 4: Token Exchange Command")
    print("-" * 30)
    
    try:
        generator = OIDCLoginGenerator("config.json")
        
        # Generate login URL with PKCE
        result = generator.generate_login_url(use_pkce=True)
        
        # Generate token exchange command
        token_cmd = generator.generate_token_exchange_command(
            auth_code="EXAMPLE_AUTH_CODE",
            redirect_uri=result['redirect_uri'],
            code_verifier=result.get('code_verifier')
        )
        
        print("Token Exchange Command:")
        print(token_cmd)
        print()
        
    except Exception as e:
        print(f"Error: {e}")
        print()
    
    # Example 5: Using test config with PKCE enabled
    print("📋 Example 5: Test Config (PKCE Enabled)")
    print("-" * 30)
    
    try:
        generator = OIDCLoginGenerator("test-config.json")
        
        result = generator.generate_login_url(
            redirect_uri="http://localhost:9000/test-callback"
        )
        
        print(f"Config: test-config.json")
        print(f"Client ID: {result['client_id']}")
        print(f"Issuer URL: {result['issuer_url']}")
        print(f"PKCE Enabled: {result['pkce_enabled']}")
        print(f"Login URL: {result['login_url']}")
        print()
        
    except Exception as e:
        print(f"Error: {e}")
        print()
    
    print("💡 Tips:")
    print("- Use different config files for different environments")
    print("- Always use HTTPS in production")
    print("- Store code verifiers securely when using PKCE")
    print("- Use random state parameters for CSRF protection")


if __name__ == '__main__':
    main()

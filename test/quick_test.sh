#!/bin/bash

# Quick test script for the OIDC Login Generator
# This script demonstrates various usage patterns

echo "🔐 OIDC Login Generator - Quick Test"
echo "===================================="
echo

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 is not installed or not in PATH"
    exit 1
fi

# Check if config files exist
if [ ! -f "../config.json" ]; then
    echo "❌ Error: config.json not found in parent directory"
    echo "Please copy config.json.sample to config.json first"
    exit 1
fi

echo "✅ Python 3 found"
echo "✅ Config file found"
echo

# Test 1: Basic usage
echo "📋 Test 1: Basic Usage"
echo "----------------------"
python3 oidc_login_generator.py
echo

# Test 2: Custom redirect URI
echo "📋 Test 2: Custom Redirect URI"
echo "------------------------------"
python3 oidc_login_generator.py --redirect-uri "http://localhost:8080/my-app/callback"
echo

# Test 3: Force PKCE
echo "📋 Test 3: Force PKCE"
echo "---------------------"
python3 oidc_login_generator.py --pkce --verbose
echo

# Test 4: Test config (PKCE enabled by default)
echo "📋 Test 4: Test Config (PKCE Enabled)"
echo "-------------------------------------"
if [ -f "../test-config.json" ]; then
    python3 oidc_login_generator.py --config ../test-config.json --verbose
else
    echo "⚠️  test-config.json not found, skipping this test"
fi
echo

# Test 5: Custom scopes and state
echo "📋 Test 5: Custom Scopes and State"
echo "----------------------------------"
python3 oidc_login_generator.py \
    --scopes "openid profile email phone address" \
    --state "my-custom-state-123" \
    --redirect-uri "http://localhost:9000/callback"
echo

echo "✅ All tests completed!"
echo
echo "💡 Usage Tips:"
echo "- Use --verbose for detailed output"
echo "- Use --pkce to force PKCE usage"
echo "- Use --no-pkce to disable PKCE"
echo "- Use --config to specify different config files"
echo "- Use --redirect-uri to customize the callback URL"
echo "- Use --scopes to specify OIDC scopes"
echo "- Use --state to set a custom state parameter"

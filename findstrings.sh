#!/bin/bash

# Find interesting strings in output files
# Improved version with better patterns and error handling

set -euo pipefail

readonly output_dir="${1:-out/}"

if [ ! -d "$output_dir" ]; then
    echo "Error: Output directory '$output_dir' not found" >&2
    exit 1
fi

# Extended list of interesting patterns
readonly searches=(
    '\-----BEGIN PRIVATE KEY-----'
    '\-----BEGIN RSA PRIVATE KEY-----'
    '\-----BEGIN DSA PRIVATE KEY-----'
    '\-----BEGIN EC PRIVATE KEY-----'
    '\-----BEGIN OPENSSH PRIVATE KEY-----'
    '\-----BEGIN PGP PRIVATE KEY-----'
    '\$1\$'                          # MD5 crypt
    '\$2a\$'                         # Blowfish crypt
    '\$2b\$'                         # Blowfish crypt
    '\$2x\$'                         # Blowfish crypt
    '\$2y\$'                         # Blowfish crypt
    '\$5\$'                          # SHA-256 crypt
    '\$6\$'                          # SHA-512 crypt
    'secret'
    'password'
    'passwd'
    'api_key'
    'api-key'
    'apikey'
    'api_secret'
    'api-secret'
    'api_secret_key'
    'api-secret-key'
    'secret_key'
    'secret-key'
    'private_key'
    'private-key'
    'access_token'
    'access-token'
    'auth_token'
    'auth-token'
    'jwt_secret'
    'jwt-secret'
    'database_password'
    'database-password'
    'db_password'
    'db-password'
    'mysql_password'
    'postgres_password'
    'mongodb_password'
    'redis_password'
    'aws_access_key_id'
    'aws_secret_access_key'
    'amazon_secret_access_key'
    'google_api_key'
    'facebook_app_secret'
    'twitter_secret'
    'github_token'
    'slack_token'
    'stripe_secret'
    'paypal_secret'
    'mailgun_api_key'
    'sendgrid_api_key'
    'twilio_auth_token'
)

echo "Searching for interesting strings in $output_dir..."

found_any=false

for pattern in "${searches[@]}"; do
    if grep --color=always -Hnri "$pattern" "$output_dir" 2>/dev/null; then
        found_any=true
    fi
done

if [ "$found_any" = false ]; then
    echo "No interesting strings found."
fi
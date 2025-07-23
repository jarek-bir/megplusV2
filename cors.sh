#!/bin/bash

# CORS misconfiguration scanner
# Improved version with better error handling

set -euo pipefail

readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'
readonly END='\033[0m'

urlsfile="${1:-}"

if [ -z "$urlsfile" ]; then
    echo "Usage: $0 <urlsfile>" >&2
    exit 1
fi

if [ ! -f "$urlsfile" ]; then
    echo "Error: File '$urlsfile' not found" >&2
    exit 1
fi

CORS=()
CREDS=()

# Function to check Access-Control-Allow-Origin
checkacao() {
    local url="$1"
    local origin="$2"
    
    curl -vs --max-time 9 --connect-timeout 5 "$url" -H "Origin: $origin" 2>&1 | \
        grep -i "< Access-Control-Allow-Origin: $origin" &> /dev/null
}

# Function to check Access-Control-Allow-Credentials
checkacac() {
    local url="$1"
    local origin="$2"
    
    curl -vs --max-time 9 --connect-timeout 5 "$url" -H "Origin: $origin" 2>&1 | \
        grep -i "< Access-Control-Allow-Credentials: true" &> /dev/null
}

while read -r url; do
    domain=$(echo "$url" | sed -E 's#https?://([^/]*)/?.*#\1#')

    for origin in https://evil.com null https://$domain.evil.com https://${domain}evil.com; do
        if checkacao "$url" "$origin"; then
            CORS+=("$url might be vulnerable with origin '$origin'")
            if checkacac "$url" "$origin"; then           
                CREDS+=("$url with origin '$origin' has Allow-Credentials: true")
            fi
        fi
        sleep 2
    done
done < $urlsfile

if [[ ${#CORS[@]} -gt 0 ]]; then
	printf "${YELLOW}[i]${END} Potentially vulnerable targets:\\n"
	printf '%s\n' "${CORS[@]}"
fi
if [[ ${#CREDS[@]} -gt 0 ]]; then
	printf "${YELLOW}[i]${END} Has 'Allow-Credentials: true':\\n"
	printf '%s\n' "${CREDS[@]}"
fi
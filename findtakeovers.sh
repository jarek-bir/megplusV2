#!/bin/bash

# Find potential subdomain takeovers
# Improved version with extended patterns and better error handling

set -euo pipefail

readonly output_dir="${1:-out/}"

if [ ! -d "$output_dir" ]; then
    echo "Error: Output directory '$output_dir' not found" >&2
    exit 1
fi

# Extended list of takeover patterns
readonly searches=(
    "There is no app configured at that hostname"
    "NoSuchBucket"
    "No Such Account"
    "You're Almost There"
    "a GitHub Pages site here"
    "this shop is currently unavailable"
    "There's nothing here"
    "The site you were looking for couldn't be found"
    "The request could not be satisfied"
    "project not found"
    "Your CNAME settings"
    "The resource that you are attempting to access does not exist or you don't have the necessary permissions to view it."
    "Domain mapping upgrade for this domain not found"
    "The feed has not been found"
    "This UserVoice subdomain is currently available!"
    "Sorry, this shop is currently unavailable"
    "You can claim it now at"
    "Whatever you were looking for doesn't currently exist at this address"
    "The site configured at this address does not contain the requested file"
    "Repository not found"
    "Trying to access your account?"
    "Project doesnt exist... yet!"
    "Help Center Closed"
    "The specified bucket does not exist"
    "The resource you are looking for has been removed"
    "No settings were found for this company:"
    "No such app"
    "is not a registered InCloud YouTrack"
    "Unrecognized domain"
    "Invalid request"
    "Not found"
    "We could not find what you're looking for"
    "No Site For Domain"
    "No site configured at this address"
    "This domain is not configured"
    "Error 404"
    "This application does not exist"
    "There isn't a GitHub Pages site here"
    "Deploy your application"
)

echo "Searching for potential subdomain takeovers in $output_dir..."

found_any=false

for pattern in "${searches[@]}"; do
    if grep --color=always -Hnri "$pattern" "$output_dir" 2>/dev/null; then
        found_any=true
    fi
done

if [ "$found_any" = false ]; then
    echo "No potential subdomain takeovers found."
fi

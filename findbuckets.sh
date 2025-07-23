#!/bin/bash

# Find cloud storage buckets in output files
# Improved version with better patterns and error handling

set -euo pipefail

readonly output_dir="${1:-out/}"

if [ ! -d "$output_dir" ]; then
    echo "Error: Output directory '$output_dir' not found" >&2
    exit 1
fi

echo "Searching for cloud storage buckets in $output_dir..."

# Search for AWS S3, DigitalOcean Spaces, Azure Blob Storage, and Google Cloud Storage
if ! grep --color=always -Pri \
    '(/|2F)?\K([\w\.\-_]+)\.(amazonaws\.com|s3\.amazonaws\.com|s3-[a-z0-9\-]+\.amazonaws\.com|digitaloceanspaces\.com|blob\.core\.windows\.net|storage\.googleapis\.com|storage\.cloud\.google\.com)(/|%2F)?([\w\.\-_]+)?' \
    "$output_dir" 2>/dev/null; then
    echo "No cloud storage buckets found."
fi

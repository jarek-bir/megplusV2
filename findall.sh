#!/bin/bash

# Universal Security Findings Extractor for meg+
# Analyzes meg output for credentials, vulnerabilities, and interesting findings

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m' 
readonly CYAN='\033[0;36m'
readonly RED='\033[0;31m'
readonly BLUE='\033[0;34m'
readonly BOLD='\033[1m'
readonly END='\033[0m'

output_dir="${1:-out/}"
inactive_domains="${2:-}"

if [ ! -d "$output_dir" ]; then
    echo -e "${RED}Error: Output directory '$output_dir' not found${END}" >&2
    exit 1
fi

echo -e "${CYAN}${BOLD}🔍 MEG+ Universal Security Findings Scanner${END}"
echo -e "${BLUE}Scanning: $output_dir${END}"
echo "================================================================"

# Function to search and report findings
search_pattern() {
    local category="$1"
    local pattern="$2" 
    local color="$3"
    local description="$4"
    
    local findings=$(grep -r -i -E "$pattern" "$output_dir" 2>/dev/null | wc -l)
    
    if [ "$findings" -gt 0 ]; then
        echo -e "${color}${BOLD}[$category] $description${END}"
        echo -e "${color}Found: $findings matches${END}"
        
        # Show examples with better formatting
        grep -r -i -E "$pattern" "$output_dir" 2>/dev/null | head -5 | while IFS=':' read -r file rest; do
            domain=$(basename "$(dirname "$file")" 2>/dev/null || echo "unknown")
            clean_match=$(echo "$rest" | sed 's/[[:space:]]\+/ /g' | cut -c1-80)
            echo -e "  ${color}• $domain${END}: $clean_match..."
        done
        echo
        return 0
    fi
    return 1
}

# Function to count findings by severity
count_findings() {
    local pattern="$1"
    grep -r -i -E "$pattern" "$output_dir" 2>/dev/null | wc -l
}

# Initialize counters
critical_count=0
high_count=0
medium_count=0
info_count=0

# 1. CRITICAL - CREDENTIALS & SECRETS
echo -e "${RED}${BOLD}🚨 CRITICAL SEVERITY${END}"
if search_pattern "CREDS" "password\s*[:=]\s*['\"]?[^'\"\s]{3,}" "$RED" "Exposed passwords"; then
    ((critical_count += $(count_findings "password\s*[:=]\s*['\"]?[^'\"\s]{3,}")))
fi
if search_pattern "CREDS" "api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9]{10,}" "$RED" "API keys"; then
    ((critical_count += $(count_findings "api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9]{10,}")))
fi
if search_pattern "CREDS" "secret\s*[:=]\s*['\"]?[a-zA-Z0-9]{10,}" "$RED" "Secret tokens"; then
    ((critical_count += $(count_findings "secret\s*[:=]\s*['\"]?[a-zA-Z0-9]{10,}")))
fi
if search_pattern "CREDS" "token\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}" "$RED" "Auth tokens"; then
    ((critical_count += $(count_findings "token\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}")))
fi
if search_pattern "CREDS" "aws_access_key_id|aws_secret_access_key" "$RED" "AWS credentials"; then
    ((critical_count += $(count_findings "aws_access_key_id|aws_secret_access_key")))
fi
if search_pattern "CREDS" "private.*key|-----BEGIN.*PRIVATE.*KEY" "$RED" "Private keys"; then
    ((critical_count += $(count_findings "private.*key|-----BEGIN.*PRIVATE.*KEY")))
fi
if search_pattern "CREDS" "connectionstring|connection.*string.*password" "$RED" "Database connections"; then
    ((critical_count += $(count_findings "connectionstring|connection.*string.*password")))
fi

# 2. HIGH SEVERITY - VULNERABILITIES
echo -e "${RED}${BOLD}🔥 HIGH SEVERITY${END}"
if search_pattern "XSS" "<script|javascript:|onload\s*=|onerror\s*=|alert\(|prompt\(|confirm\(" "$RED" "XSS patterns"; then
    ((high_count += $(count_findings "<script|javascript:|onload\s*=|onerror\s*=|alert\(|prompt\(|confirm\(")))
fi
if search_pattern "SQLI" "sql.*error|mysql.*error|syntax.*error.*near|ORA-[0-9]{5}" "$RED" "SQL error messages"; then
    ((high_count += $(count_findings "sql.*error|mysql.*error|syntax.*error.*near|ORA-[0-9]{5}")))
fi
if search_pattern "LFI" "\.\./.*\.\./|\.\.\\\\.*\.\.\\\\|/etc/passwd|/etc/shadow|/proc/self/environ" "$RED" "Path traversal"; then
    ((high_count += $(count_findings "\.\./.*\.\./|\.\.\\\\.*\.\.\\\\|/etc/passwd|/etc/shadow|/proc/self/environ")))
fi
if search_pattern "SSRF" "localhost|127\.0\.0\.1|169\.254\.|metadata|:22|:3389|:445" "$RED" "SSRF indicators"; then
    ((high_count += $(count_findings "localhost|127\.0\.0\.1|169\.254\.|metadata|:22|:3389|:445")))
fi
if search_pattern "XXE" "<!ENTITY|<!DOCTYPE.*ENTITY|SYSTEM.*file://" "$RED" "XXE patterns"; then
    ((high_count += $(count_findings "<!ENTITY|<!DOCTYPE.*ENTITY|SYSTEM.*file://")))
fi
if search_pattern "RCE" "eval\(|exec\(|system\(|shell_exec|passthru|popen|proc_open" "$RED" "Code execution patterns"; then
    ((high_count += $(count_findings "eval\(|exec\(|system\(|shell_exec|passthru|popen|proc_open")))
fi

# 3. MEDIUM SEVERITY - CONFIG & DEBUG
echo -e "${YELLOW}${BOLD}⚠️  MEDIUM SEVERITY${END}"
if search_pattern "CONFIG" "200 OK.*\.(env|config|conf|ini|yaml|yml|json|xml|properties)(\?|$)" "$YELLOW" "Exposed config files"; then
    ((medium_count += $(count_findings "200 OK.*\.(env|config|conf|ini|yaml|yml|json|xml|properties)(\?|$)")))
fi
if search_pattern "DEBUG" "debug.*=.*true|development.*mode|trace.*enabled|verbose.*=.*true" "$YELLOW" "Debug mode enabled"; then
    ((medium_count += $(count_findings "debug.*=.*true|development.*mode|trace.*enabled|verbose.*=.*true")))
fi
if search_pattern "STACK" "stack.*trace|exception.*trace|fatal.*error|uncaught.*exception" "$YELLOW" "Stack traces/errors"; then
    ((medium_count += $(count_findings "stack.*trace|exception.*trace|fatal.*error|uncaught.*exception")))
fi
if search_pattern "DB" "database.*host|db.*host|mysql.*host|mongodb.*host|redis.*host" "$YELLOW" "Database configs"; then
    ((medium_count += $(count_findings "database.*host|db.*host|mysql.*host|mongodb.*host|redis.*host")))
fi
if search_pattern "BACKUP" "200 OK.*(backup|dump|export|archive|\.bak|\.old|\.orig)" "$YELLOW" "Backup files"; then
    ((medium_count += $(count_findings "200 OK.*(backup|dump|export|archive|\.bak|\.old|\.orig)")))
fi

# 4. INFO - INTERESTING ENDPOINTS
echo -e "${CYAN}${BOLD}ℹ️  INFORMATIONAL${END}"
if search_pattern "ADMIN" "200 OK.*(admin|dashboard|console|panel|manager|control)" "$CYAN" "Admin interfaces"; then
    ((info_count += $(count_findings "200 OK.*(admin|dashboard|console|panel|manager|control)")))
fi
if search_pattern "API" "200 OK.*(api|rest|graphql|swagger|openapi)" "$CYAN" "API endpoints"; then
    ((info_count += $(count_findings "200 OK.*(api|rest|graphql|swagger|openapi)")))
fi
if search_pattern "UPLOAD" "200 OK.*(upload|file|attachment|media)" "$CYAN" "Upload endpoints"; then
    ((info_count += $(count_findings "200 OK.*(upload|file|attachment|media)")))
fi
if search_pattern "DEV" "200 OK.*(dev|test|staging|demo|sandbox)" "$CYAN" "Development environments"; then
    ((info_count += $(count_findings "200 OK.*(dev|test|staging|demo|sandbox)")))
fi

# 5. CLOUD & STORAGE
echo -e "${BLUE}${BOLD}☁️  CLOUD & STORAGE${END}"
if search_pattern "S3" "amazonaws\.com|s3\.amazonaws\.com|s3-.*\.amazonaws\.com" "$BLUE" "AWS S3 buckets"; then
    ((info_count += $(count_findings "amazonaws\.com|s3\.amazonaws\.com|s3-.*\.amazonaws\.com")))
fi
if search_pattern "AZURE" "blob\.core\.windows\.net|azurewebsites\.net|sharepoint\.com" "$BLUE" "Azure storage"; then
    ((info_count += $(count_findings "blob\.core\.windows\.net|azurewebsites\.net|sharepoint\.com")))
fi
if search_pattern "GCP" "storage\.googleapis\.com|storage\.cloud\.google\.com|appspot\.com" "$BLUE" "Google Cloud storage"; then
    ((info_count += $(count_findings "storage\.googleapis\.com|storage\.cloud\.google\.com|appspot\.com")))
fi
if search_pattern "DIGITAL" "digitaloceanspaces\.com|nyc[0-9]\.digitaloceanspaces\.com" "$BLUE" "DigitalOcean Spaces"; then
    ((info_count += $(count_findings "digitaloceanspaces\.com|nyc[0-9]\.digitaloceanspaces\.com")))
fi

# 6. SUBDOMAIN TAKEOVER
echo -e "${RED}${BOLD}🎯 SUBDOMAIN TAKEOVER${END}"
if search_pattern "TAKEOVER" "NoSuchBucket|NoSuchKey|No such app|There isn't a GitHub Pages site here" "$RED" "Takeover indicators"; then
    ((high_count += $(count_findings "NoSuchBucket|NoSuchKey|No such app|There isn't a GitHub Pages site here")))
fi
if search_pattern "TAKEOVER" "project not found|Repository not found|404.*github\.io" "$RED" "Missing repositories"; then
    ((high_count += $(count_findings "project not found|Repository not found|404.*github\.io")))
fi
if search_pattern "TAKEOVER" "herokucdn\.com|fastly\.com.*404|cloudfront\.net.*NoSuchDistribution" "$RED" "CDN takeovers"; then
    ((high_count += $(count_findings "herokucdn\.com|fastly\.com.*404|cloudfront\.net.*NoSuchDistribution")))
fi

# 7. TECHNOLOGY FINGERPRINTING
echo -e "${GREEN}${BOLD}🔍 TECHNOLOGY DETECTION${END}"
if search_pattern "TECH" "X-Powered-By:|Server:|X-Framework:|X-AspNet-Version:" "$GREEN" "Technology headers"; then
    ((info_count += $(count_findings "X-Powered-By:|Server:|X-Framework:|X-AspNet-Version:")))
fi
if search_pattern "CMS" "wp-content|wp-admin|wordpress|drupal|joomla|typo3" "$GREEN" "CMS detection"; then
    ((info_count += $(count_findings "wp-content|wp-admin|wordpress|drupal|joomla|typo3")))
fi
if search_pattern "FRAMEWORK" "laravel|symfony|django|rails|express|spring|struts" "$GREEN" "Framework detection"; then
    ((info_count += $(count_findings "laravel|symfony|django|rails|express|spring|struts")))
fi

# 8. ANALYZE INACTIVE DOMAINS (if provided)
if [ -n "$inactive_domains" ] && [ -f "$inactive_domains" ]; then
    echo -e "${YELLOW}${BOLD}🔍 INACTIVE DOMAIN ANALYSIS${END}"
    
    # Pattern analysis of inactive domains
    local dev_domains=$(grep -i -E "(dev|test|staging|demo|sandbox)" "$inactive_domains" 2>/dev/null | wc -l)
    local api_domains=$(grep -i -E "(api|rest|graphql|v[0-9])" "$inactive_domains" 2>/dev/null | wc -l)
    local admin_domains=$(grep -i -E "(admin|console|panel|dashboard)" "$inactive_domains" 2>/dev/null | wc -l)
    local legacy_domains=$(grep -i -E "(old|legacy|archive|backup)" "$inactive_domains" 2>/dev/null | wc -l)
    
    echo -e "${YELLOW}Development environments: $dev_domains${END}"
    echo -e "${YELLOW}API endpoints: $api_domains${END}"
    echo -e "${YELLOW}Admin interfaces: $admin_domains${END}"
    echo -e "${YELLOW}Legacy systems: $legacy_domains${END}"
    echo
fi

# 9. SUMMARY STATISTICS
echo -e "${BOLD}📊 VULNERABILITY SUMMARY${END}"
echo "================================================================"
total_domains=$(find "$output_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
total_files=$(find "$output_dir" -type f 2>/dev/null | wc -l) 
total_200=$(grep -r "200 OK" "$output_dir" 2>/dev/null | wc -l)
total_403=$(grep -r "403" "$output_dir" 2>/dev/null | wc -l)
total_500=$(grep -r "50[0-9]" "$output_dir" 2>/dev/null | wc -l)

echo -e "${CYAN}Scanned domains: $total_domains${END}"
echo -e "${CYAN}Total responses: $total_files${END}"
echo -e "${GREEN}Successful (200): $total_200${END}"
echo -e "${YELLOW}Forbidden (403): $total_403${END}" 
echo -e "${RED}Server errors (5xx): $total_500${END}"
echo

echo -e "${BOLD}Security Findings by Severity:${END}"
echo -e "${RED}🚨 Critical: $critical_count${END}"
echo -e "${RED}🔥 High: $high_count${END}"
echo -e "${YELLOW}⚠️  Medium: $medium_count${END}"
echo -e "${CYAN}ℹ️  Info: $info_count${END}"
echo

total_findings=$((critical_count + high_count + medium_count + info_count))
echo -e "${BOLD}Total Security Findings: $total_findings${END}"

if [ "$critical_count" -gt 0 ]; then
    echo -e "${RED}${BOLD}⚠️  IMMEDIATE ATTENTION REQUIRED - Critical findings detected!${END}"
elif [ "$high_count" -gt 0 ]; then
    echo -e "${RED}${BOLD}⚠️  High severity findings require investigation${END}"
fi

echo
echo -e "${CYAN}Full results available in: $output_dir${END}"
echo -e "${CYAN}Use './browse_results.sh' for detailed exploration${END}"

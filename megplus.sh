#!/bin/bash

# meg+ - Automated reconnaissance wrapper for TomNomNom's meg
# Refactored version with improved error handling and structure

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Color definitions for terminal output
readonly GREEN='\033[0;32m'    # Success messages
readonly YELLOW='\033[0;33m'   # Warnings and info
readonly CYAN='\033[0;36m'     # Banner and highlights
readonly RED='\033[0;31m'      # Error messages
readonly BLUE='\033[0;34m'     # Additional info
readonly BOLD='\033[1m'        # Bold text
readonly DIM='\033[2m'         # Dimmed text
readonly END='\033[0m'         # Reset color

# Global variables
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUTPUT_DIR="${SCRIPT_DIR}/out"

# Default settings
CLEAN_OLD_RESULTS=true

# Function to display usage information
show_usage() {
    echo "meg+ - Automated reconnaissance wrapper"
    echo
    echo "Usage:"
    echo "  1) Target list of domains:        ./megplus.sh <list of domains>"
    echo "  2) Target all HackerOne programs: ./megplus.sh -x <H1 X-Auth-Token>"
    echo "  3) Run Sublist3r first:           ./megplus.sh -s <single host>"
    echo "  4) Use custom paths list:         ./megplus.sh -p <domains file>"
    echo "  5) Show results summary:          ./megplus.sh -r"
    echo "  6) Run Subfinder first:           ./megplus.sh -sf <single host>"
    echo "  7) Run both subdomain tools:      ./megplus.sh -all <single host>"
    echo
    echo "Examples:"
    echo "  ./megplus.sh domains"
    echo "  ./megplus.sh -x XXXXXXXXXXXXXXXX"
    echo "  ./megplus.sh -s example.com"
    echo "  ./megplus.sh -sf example.com"
    echo "  ./megplus.sh -all example.com"
    echo "  ./megplus.sh -p domains"
    echo "  ./megplus.sh -r"
    echo
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -p, --paths       Use curated paths from lists/paths.txt for scanning"
    echo "  -r, --results     Show summary of previous scan results"
    echo "  -sf, --subfinder  Run subfinder for subdomain enumeration"
    echo "  -all, --all-subs  Run both sublist3r AND subfinder for maximum coverage"
    echo "  --keep-old        Don't clean old results from output directory"
    echo "  --no-clean        Same as --keep-old"
    exit 1
}

# Function to log messages with color
log() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "info")
            printf "${GREEN}[+]${END} %s\n" "$message" >&2
            ;;
        "warn")
            printf "${YELLOW}[!]${END} %s\n" "$message" >&2
            ;;
        "error")
            printf "${RED}[-]${END} %s\n" "$message" >&2
            ;;
        "note")
            printf "${YELLOW}[i]${END} %s\n" "$message" >&2
            ;;
    esac
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for required tools
    local deps=("meg" "curl" "grep" "sed" "tr" "uniq")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    # Check for meg specifically
    if ! command -v meg &> /dev/null; then
        log "error" "meg is required but not installed."
        log "note" "Install it from: https://github.com/tomnomnom/meg#install"
        return 1
    fi
    
    # Check for optional tools
    if ! command -v sublist3r &> /dev/null; then
        log "warn" "sublist3r not found - subdomain enumeration (-s option) will not work"
    fi
    
    if ! command -v subfinder &> /dev/null; then
        log "warn" "subfinder not found - subfinder enumeration (-sf option) will not work"
    fi
    
    if ! command -v httprobe &> /dev/null; then
        log "warn" "httprobe not found - will use basic host resolution instead"
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log "error" "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    return 0
}

# Function to setup output directory
setup_output_dir() {
    # Clean old results if requested and directory exists
    if [ "$CLEAN_OLD_RESULTS" = true ] && [ -d "$OUTPUT_DIR" ]; then
        log "info" "Cleaning old results from $OUTPUT_DIR"
        rm -rf "$OUTPUT_DIR"/*
    fi
    
    # Create fresh output directory
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        log "info" "Created output directory: $OUTPUT_DIR"
    else
        if [ "$CLEAN_OLD_RESULTS" = true ]; then
            log "info" "Using clean output directory: $OUTPUT_DIR"
        else
            log "info" "Using existing output directory: $OUTPUT_DIR (keeping old results)"
        fi
    fi
}

# Function to clean and normalize domain list
normalize_domains() {
    local input_file="$1"
    local output_file="$2"
    
    if [ ! -f "$input_file" ]; then
        log "error" "Input file not found: $input_file"
        return 1
    fi
    
    # Clean and normalize domain list
    sed -E 's#https?://##I' "$input_file" | \
    sed -E 's#/.*##' | \
    sed -E 's#^\*\.?##' | \
    sed -E 's#,#\n#g' | \
    tr '[:upper:]' '[:lower:]' | \
    grep -v '^[[:space:]]*$' | \
    sort | \
    uniq | \
    sed -e 's/^/https:\/\//' > "$output_file"
    
    local count=$(wc -l < "$output_file")
    log "info" "Normalized $count domains to $output_file"
}

# Function to fetch HackerOne targets
fetch_hackerone_targets() {
    local token="$1"
    local temp_file="${SCRIPT_DIR}/temp_h1"
    local output_file="${SCRIPT_DIR}/domains-plus"
    
    log "info" "Fetching all in-scope targets from HackerOne..."
    
    if ! php "${SCRIPT_DIR}/fetch.php" "$token" > "$temp_file"; then
        log "error" "Failed to fetch HackerOne targets"
        rm -f "$temp_file"
        return 1
    fi
    
    normalize_domains "$temp_file" "$output_file"
    rm -f "$temp_file"
    echo "$output_file"
}

# Function to run Sublist3r enumeration
run_sublist3r() {
    local domain="$1"
    local domains_sub="${SCRIPT_DIR}/domains-sub"
    local output_file="${SCRIPT_DIR}/domains-plus"
    local temp_output="${SCRIPT_DIR}/temp_sublist3r"
    
    log "info" "Running Sublist3r against $domain..."
    
    # Check if sublist3r binary exists
    if ! command -v sublist3r &> /dev/null; then
        log "error" "sublist3r binary not found in PATH. Please install or create symlink."
        return 1
    fi
    
    # Run Sublist3r
    if ! sublist3r -d "$domain" -o "$domains_sub" > /dev/null 2>&1; then
        log "error" "Sublist3r failed"
        return 1
    fi
    
    # Validate discovered domains (no limits - process all)
    log "info" "Validating discovered subdomains..."
    local processed=0
    
    while IFS= read -r line; do
        # Extract domain from line - get the last word that looks like a domain
        potential_domain=$(echo "$line" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | head -1)
        
        # Skip empty results and validate basic domain format
        if [[ -n "$potential_domain" && "$potential_domain" =~ \.[a-zA-Z]{2,}$ ]]; then
            echo "$potential_domain"
        fi
        ((processed++))
    done < "$domains_sub" > "$temp_output"
    
    log "info" "Processed $processed potential subdomains from Sublist3r"
    
    # Use httprobe to validate and get HTTP/HTTPS URLs if available
    if command -v httprobe &> /dev/null && [ -s "$temp_output" ]; then
        log "info" "Probing HTTP/HTTPS endpoints with httprobe..."
        local probe_output="${SCRIPT_DIR}/temp_probe"
        cat "$temp_output" | httprobe -c 100 -t 3000 > "$probe_output" 2>/dev/null || true
        
        if [ -s "$probe_output" ]; then
            # Use httprobe results (already include http/https)
            sort "$probe_output" | uniq > "$output_file"
            local final_count=$(wc -l < "$output_file")
            log "info" "httprobe found $final_count active HTTP/HTTPS endpoints"
            rm -f "$probe_output"
        else
            log "warn" "httprobe found no live endpoints, using domain list with https prefix"
            normalize_domains "$temp_output" "$output_file"
        fi
    else
        # Fallback to normalize_domains if httprobe not available
        normalize_domains "$temp_output" "$output_file"
    fi
    
    # Check if we got any valid domains
    if [ ! -s "$output_file" ]; then
        log "warn" "No valid subdomains found for $domain"
        # Create minimal target file with just the main domain
        echo "https://$domain" > "$output_file"
    fi
    rm -f "$domains_sub" "$temp_output"
    echo "$output_file"
}

# Function to run Subfinder enumeration
run_subfinder() {
    local domain="$1"
    local domains_subfinder="${SCRIPT_DIR}/domains-subfinder"
    local output_file="${SCRIPT_DIR}/domains-plus"
    local temp_output="${SCRIPT_DIR}/temp_subfinder"
    
    log "info" "Running Subfinder against $domain..."
    
    # Check if subfinder binary exists
    if ! command -v subfinder &> /dev/null; then
        log "error" "subfinder binary not found in PATH. Please install subfinder."
        return 1
    fi
    
    # Run Subfinder with silent mode and output to file
    if ! subfinder -d "$domain" -o "$domains_subfinder" > /dev/null 2>&1; then
        log "error" "Subfinder failed"
        return 1
    fi
    
    # Process subfinder results
    log "info" "Processing Subfinder results..."
    local processed=0
    
    while IFS= read -r line; do
        # Subfinder already outputs clean domains, just validate format
        if [[ -n "$line" && "$line" =~ \.[a-zA-Z]{2,}$ ]]; then
            echo "$line"
        fi
        ((processed++))
    done < "$domains_subfinder" > "$temp_output"
    
    log "info" "Processed $processed subdomains from Subfinder"
    
    # Use httprobe to validate and get HTTP/HTTPS URLs if available
    if command -v httprobe &> /dev/null && [ -s "$temp_output" ]; then
        log "info" "Probing HTTP/HTTPS endpoints with httprobe..."
        local probe_output="${SCRIPT_DIR}/temp_probe_sf"
        cat "$temp_output" | httprobe -c 100 -t 3000 > "$probe_output" 2>/dev/null || true
        
        if [ -s "$probe_output" ]; then
            # Use httprobe results (already include http/https)
            sort "$probe_output" | uniq > "$output_file"
            local final_count=$(wc -l < "$output_file")
            log "info" "httprobe found $final_count active HTTP/HTTPS endpoints"
            rm -f "$probe_output"
        else
            log "warn" "httprobe found no live endpoints, using domain list with https prefix"
            normalize_domains "$temp_output" "$output_file"
        fi
    else
        # Fallback to normalize_domains if httprobe not available
        normalize_domains "$temp_output" "$output_file"
    fi
    
    # Check if we got any valid domains
    if [ ! -s "$output_file" ]; then
        log "warn" "No valid subdomains found for $domain"
        # Create minimal target file with just the main domain
        echo "https://$domain" > "$output_file"
    fi
    rm -f "$domains_subfinder" "$temp_output"
    echo "$output_file"
}

# Function to run BOTH subdomain tools for maximum coverage
run_all_subdomain_tools() {
    local domain="$1"
    local output_file="${SCRIPT_DIR}/domains-plus"
    local combined_temp="${SCRIPT_DIR}/temp_combined_subs"
    
    log "info" "Running comprehensive subdomain enumeration with multiple tools..."
    echo
    
    # Run both tools and collect results
    local sublist3r_results=""
    local subfinder_results=""
    
    # Run Sublist3r
    if command -v sublist3r &> /dev/null; then
        log "info" "Phase 1: Running Sublist3r..."
        local temp_sublist3r_file="${SCRIPT_DIR}/temp_sublist3r_combined"
        if run_sublist3r_internal "$domain" "$temp_sublist3r_file"; then
            sublist3r_results="$temp_sublist3r_file"
        fi
    else
        log "warn" "Sublist3r not available, skipping..."
    fi
    
    # Run Subfinder  
    if command -v subfinder &> /dev/null; then
        log "info" "Phase 2: Running Subfinder..."
        local temp_subfinder_file="${SCRIPT_DIR}/temp_subfinder_combined"
        if run_subfinder_internal "$domain" "$temp_subfinder_file"; then
            subfinder_results="$temp_subfinder_file"
        fi
    else
        log "warn" "Subfinder not available, skipping..."
    fi
    
    # Combine results from both tools
    log "info" "Combining results from all subdomain enumeration tools..."
    > "$combined_temp"  # Create empty file
    
    # Add results from both tools
    if [ -n "$sublist3r_results" ] && [ -f "$sublist3r_results" ]; then
        cat "$sublist3r_results" >> "$combined_temp"
    fi
    
    if [ -n "$subfinder_results" ] && [ -f "$subfinder_results" ]; then
        cat "$subfinder_results" >> "$combined_temp"
    fi
    
    # Remove duplicates and sort
    if [ -s "$combined_temp" ]; then
        sort "$combined_temp" | uniq > "${combined_temp}.sorted"
        mv "${combined_temp}.sorted" "$combined_temp"
        
        local total_unique=$(wc -l < "$combined_temp")
        log "info" "Combined $total_unique unique subdomains from all tools"
        
        # Use httprobe on combined results
        if command -v httprobe &> /dev/null; then
            log "info" "Probing all discovered subdomains with httprobe..."
            local probe_output="${SCRIPT_DIR}/temp_probe_combined"
            cat "$combined_temp" | httprobe -c 100 -t 3000 > "$probe_output" 2>/dev/null || true
            
            if [ -s "$probe_output" ]; then
                sort "$probe_output" | uniq > "$output_file"
                local final_count=$(wc -l < "$output_file")
                log "info" "httprobe found $final_count active HTTP/HTTPS endpoints from combined results"
                rm -f "$probe_output"
            else
                log "warn" "httprobe found no live endpoints, using domain list with https prefix"
                normalize_domains "$combined_temp" "$output_file"
            fi
        else
            normalize_domains "$combined_temp" "$output_file"
        fi
    else
        log "warn" "No subdomains found by any tool"
        echo "https://$domain" > "$output_file"
    fi
    
    # Cleanup temp files
    rm -f "$combined_temp" "$sublist3r_results" "$subfinder_results"
    echo "$output_file"
}

# Internal helper for sublist3r (returns raw domains)
run_sublist3r_internal() {
    local domain="$1"
    local output_file="$2"
    local domains_sub="${SCRIPT_DIR}/domains-sub-internal"
    
    if ! sublist3r -d "$domain" -o "$domains_sub" > /dev/null 2>&1; then
        return 1
    fi
    
    while IFS= read -r line; do
        potential_domain=$(echo "$line" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | head -1)
        if [[ -n "$potential_domain" && "$potential_domain" =~ \.[a-zA-Z]{2,}$ ]]; then
            echo "$potential_domain"
        fi
    done < "$domains_sub" > "$output_file"
    
    rm -f "$domains_sub"
    return 0
}

# Internal helper for subfinder (returns raw domains)
run_subfinder_internal() {
    local domain="$1"
    local output_file="$2"
    
    if ! subfinder -d "$domain" -o "$output_file" > /dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

# Function to show quick results summary
show_results_summary() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        log "warn" "No output directory found at $OUTPUT_DIR"
        return 1
    fi
    
    log "info" "Results summary from $OUTPUT_DIR:"
    echo
    
    # Count directories (scanned domains)
    local domain_count=$(find "$OUTPUT_DIR" -maxdepth 1 -type d ! -path "$OUTPUT_DIR" | wc -l)
    log "note" "Scanned domains: $domain_count"
    
    # Show 200 OK responses
    local count_200=$(grep -r "200 OK" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    log "note" "Successful responses (200 OK): $count_200"
    
    # Show some interesting 200 responses
    if [ $count_200 -gt 0 ]; then
        echo
        log "info" "Some interesting 200 OK findings:"
        grep -r "200 OK" "$OUTPUT_DIR/" 2>/dev/null | head -5 | while IFS=':' read -r file rest; do
            domain=$(basename "$(dirname "$file")")
            # Try to extract the request path from meg's output format
            request_line=$(grep -A1 -B1 "200 OK" "$file" 2>/dev/null | grep "GET\|POST\|PUT\|DELETE" | head -1 || echo "Unknown path")
            echo "  • $domain: $request_line"
        done
    fi
    
    # Show redirects
    local count_3xx=$(grep -rE "30[1-8]" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    if [ $count_3xx -gt 0 ]; then
        echo
        log "note" "Redirects (3xx): $count_3xx"
    fi
    
    # Show forbidden/unauthorized
    local count_4xx=$(grep -rE "40[13]" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    if [ $count_4xx -gt 0 ]; then
        echo
        log "note" "Access restricted (401/403): $count_4xx"
    fi
    
    echo
    log "info" "Full results available in: $OUTPUT_DIR"
}

# Function to scan with custom paths from lists/paths.txt
scan_custom_paths() {
    local targets="$1"
    local paths_file="${SCRIPT_DIR}/lists/paths.txt"
    
    if [ ! -f "$paths_file" ]; then
        log "error" "Custom paths file not found: $paths_file"
        return 1
    fi
    
    local path_count=$(wc -l < "$paths_file")
    log "info" "Scanning with $path_count custom paths from lists/paths.txt..."
    
    if meg --delay 100 "$paths_file" "$targets" &>/dev/null; then
        log "info" "Custom paths scan completed successfully"
        
        # Show some interesting findings
        log "info" "Looking for interesting responses..."
        
        # Check for common interesting status codes and patterns
        local findings=0
        
        # Check for 200 responses
        if grep -r "200 OK" "$OUTPUT_DIR/" >/dev/null 2>&1; then
            local count_200=$(grep -r "200 OK" "$OUTPUT_DIR/" | wc -l)
            log "note" "Found $count_200 successful responses (200 OK)"
            findings=$((findings + count_200))
        fi
        
        # Check for redirects
        if grep -rE "30[1-8]" "$OUTPUT_DIR/" >/dev/null 2>&1; then
            local count_3xx=$(grep -rE "30[1-8]" "$OUTPUT_DIR/" | wc -l)
            log "note" "Found $count_3xx redirect responses (3xx)"
            findings=$((findings + count_3xx))
        fi
        
        # Check for forbidden/unauthorized
        if grep -rE "40[13]" "$OUTPUT_DIR/" >/dev/null 2>&1; then
            local count_4xx=$(grep -rE "40[13]" "$OUTPUT_DIR/" | wc -l)
            log "note" "Found $count_4xx access-restricted endpoints (401/403)"
        fi
        
        # Check for server errors
        if grep -rE "50[0-9]" "$OUTPUT_DIR/" >/dev/null 2>&1; then
            local count_5xx=$(grep -rE "50[0-9]" "$OUTPUT_DIR/" | wc -l)
            log "warn" "Found $count_5xx server errors (5xx)"
        fi
        
        log "info" "Total interesting findings: $findings"
        return 0
    else
        log "error" "Custom paths scan failed"
        return 1
    fi
}

# Function to scan for configuration files
scan_config_files() {
    local targets="$1"
    
    log "info" "Finding configuration files..."
    if meg --delay 100 "${SCRIPT_DIR}/lists/configfiles" "$targets" &>/dev/null; then
        grep -Hnri "200 ok" "$OUTPUT_DIR/" || log "note" "No configuration files found"
    else
        log "warn" "Configuration file scan failed"
    fi
}

# Function to find interesting strings
find_interesting_strings() {
    log "info" "Finding interesting strings..."
    if [ -x "${SCRIPT_DIR}/findstrings.sh" ]; then
        "${SCRIPT_DIR}/findstrings.sh" "$OUTPUT_DIR/"
    else
        log "warn" "findstrings.sh not found or not executable"
    fi
}

# Function to find cloud buckets
find_buckets() {
    log "info" "Finding AWS/DigitalOcean/Azure buckets..."
    if [ -x "${SCRIPT_DIR}/findbuckets.sh" ]; then
        "${SCRIPT_DIR}/findbuckets.sh" "$OUTPUT_DIR/"
    else
        log "warn" "findbuckets.sh not found or not executable"
    fi
}

# Function to scan for open redirects
scan_open_redirects() {
    local targets="$1"
    
    log "info" "Finding open redirects..."
    if meg --delay 100 "${SCRIPT_DIR}/lists/openredirects" "$targets" &>/dev/null; then
        grep --color -HnriE '< location: (https?:)?[/\\]{2,}example.com' "$OUTPUT_DIR/" || log "note" "No open redirects found"
    else
        log "warn" "Open redirect scan failed"
    fi
}

# Function to scan for CRLF injection
scan_crlf_injection() {
    local targets="$1"
    
    log "info" "Finding CRLF injection..."
    if meg --delay 100 "${SCRIPT_DIR}/lists/crlfinjection" "$targets" &>/dev/null; then
        grep --color -HnriE "< Set-Cookie: ?crlf" "$OUTPUT_DIR/" || log "note" "No CRLF injection found"
    else
        log "warn" "CRLF injection scan failed"
    fi
}

# Function to scan for CORS misconfigurations
scan_cors() {
    local targets="$1"
    
    log "info" "Finding CORS misconfigurations..."
    if [ -x "${SCRIPT_DIR}/cors.sh" ]; then
        "${SCRIPT_DIR}/cors.sh" "$targets"
    else
        log "warn" "cors.sh not found or not executable"
    fi
}

# Function to scan for path-based XSS
scan_path_xss() {
    local targets="$1"
    
    log "info" "Finding path-based XSS..."
    if meg "/bounty%3c%22pls" "$targets" &>/dev/null; then
        grep --color -Hrie '(bounty<|"pls)' "$OUTPUT_DIR/" || log "note" "No path-based XSS found"
    else
        log "warn" "Path-based XSS scan failed"
    fi
}

# Function to scan for subdomain takeovers
scan_takeovers() {
    log "info" "Searching for (sub)domain takeovers..."
    if [ -x "${SCRIPT_DIR}/findtakeovers.sh" ]; then
        "${SCRIPT_DIR}/findtakeovers.sh"
    else
        log "warn" "findtakeovers.sh not found or not executable"
    fi
}

# Function to run waybackurls
run_waybackurls() {
    local targets="$1"
    
    log "info" "Running waybackurls..."
    if command -v waybackurls &> /dev/null; then
        if cat "$targets" | waybackurls > "${OUTPUT_DIR}/urls"; then
            log "note" "Wayback URLs saved to '${OUTPUT_DIR}/urls'"
        else
            log "warn" "waybackurls failed"
        fi
    else
        log "warn" "waybackurls not installed"
    fi
}

# Function to display banner
show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
                                                                          
   88888b.d88b.   .d88b.   .d88b.    888   
   888  888  88b d8P  Y8b d88P 88b 8888888 
   888  888  888 88888888 888  888   888   
   888  888  888 Y8b.     Y88b 888         
   888  888  888   Y8888    Y88888         
                               888         
EOF
    echo -e "   ${GREEN}Automate meg${END}           ${CYAN}Y8b d88P${END}"
    echo -e "   ${GREEN}By TomNomNom${END}            ${CYAN}YYY88P${END}"
    echo -e "   ${GREEN}& EdOverflow${END}"
    echo -e "${END}"
    echo
}

# Function to run all scans
run_all_scans() {
    local targets="$1"
    
    # Ensure output directory exists
    setup_output_dir
    
    # Run all scan modules
    scan_config_files "$targets"
    echo
    
    find_interesting_strings
    echo
    
    find_buckets
    echo
    
    scan_open_redirects "$targets"
    echo
    
    scan_crlf_injection "$targets"
    echo
    
    scan_cors "$targets"
    echo
    
    scan_path_xss "$targets"
    echo
    
    scan_takeovers
    echo
    
    run_waybackurls "$targets"
    echo
}

# Function to cleanup temporary files
cleanup() {
    local files=("temp" "domains-plus" "domains-sub" "output")
    
    for file in "${files[@]}"; do
        if [ -f "${SCRIPT_DIR}/$file" ]; then
            rm -f "${SCRIPT_DIR}/$file"
        fi
    done
}

# Function to run comprehensive security analysis
analyze_all_findings() {
    local helper_script="${SCRIPT_DIR}/findall.sh"
    
    if [ -f "$helper_script" ]; then
        log "info" "Running comprehensive security analysis..."
        echo
        bash "$helper_script" "$OUTPUT_DIR"
    else
        log "warn" "Security analysis helper not found: $helper_script"
        show_results_summary
    fi
}

# Function to show completion message
show_completion() {
    log "note" "Done scanning -- all output located in $OUTPUT_DIR"
    echo
    cat << 'EOF'
          _,-.     --------------------
  ,-. ,--'  o ) -(   Frogs find bugs!   )
  \(,' '  ,,-'     --------------------
 ,-.\-.__,\\_
 \('--'    '\ 
EOF
}

# Main function
main() {
    local targets=""
    local use_custom_paths=false
    
    # Parse command line arguments for flags first
    while [[ $# -gt 0 ]]; do
        case "$1" in
            "--keep-old" | "--no-clean")
                CLEAN_OLD_RESULTS=false
                shift
                ;;
            "-h" | "--help")
                show_usage
                ;;
            *)
                break  # Exit loop for main argument processing
                ;;
        esac
    done
    
    # Parse main command line arguments
    case "${1:-}" in
        "" | "-h" | "--help")
            show_usage
            ;;
        "-r" | "--results")
            show_results_summary
            exit 0
            ;;
        "-x")
            if [ -z "${2:-}" ]; then
                log "error" "HackerOne X-Auth-Token required"
                show_usage
            fi
            targets=$(fetch_hackerone_targets "$2")
            ;;
        "-s")
            if [ -z "${2:-}" ]; then
                log "error" "Domain required for Sublist3r scan"
                show_usage
            fi
            targets=$(run_sublist3r "$2")
            ;;
        "-sf" | "--subfinder")
            if [ -z "${2:-}" ]; then
                log "error" "Domain required for Subfinder scan"
                show_usage
            fi
            targets=$(run_subfinder "$2")
            ;;
        "-all" | "--all-subs")
            if [ -z "${2:-}" ]; then
                log "error" "Domain required for comprehensive subdomain scan"
                show_usage
            fi
            targets=$(run_all_subdomain_tools "$2")
            ;;
        "-p" | "--paths")
            if [ -z "${2:-}" ]; then
                log "error" "Domain list file required for custom paths scan"
                show_usage
            fi
            if [ ! -f "$2" ]; then
                log "error" "Domain list file not found: $2"
                exit 1
            fi
            local output_file="$2-plus"
            normalize_domains "$2" "$output_file"
            targets="$output_file"
            use_custom_paths=true
            ;;
        *)
            if [ ! -f "$1" ]; then
                log "error" "Domain list file not found: $1"
                exit 1
            fi
            local output_file="$1-plus"
            normalize_domains "$1" "$output_file"
            targets="$output_file"
            ;;
    esac
    
    # Validate targets file
    if [ -z "$targets" ] || [ ! -f "$targets" ]; then
        log "error" "No valid targets file generated"
        exit 1
    fi
    
    # Show banner
    show_banner
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Run scans based on options
    if [ "$use_custom_paths" = true ]; then
        # Ensure output directory exists
        setup_output_dir
        
        # Run only custom paths scan
        scan_custom_paths "$targets"
    else
        # Run all scans
        run_all_scans "$targets"
    fi
    
    # Run comprehensive security analysis
    analyze_all_findings
    
    # Show completion message
    show_completion
    
    # Cleanup (optional - commented out to preserve files)
    # cleanup
}

# Trap to cleanup on exit
trap cleanup EXIT

# Run main function with all arguments
main "$@"

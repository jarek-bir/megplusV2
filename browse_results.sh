#!/bin/bash

# meg+ Results Browser
# Quick script to browse meg+ scan results

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUTPUT_DIR="${SCRIPT_DIR}/out"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly END='\033[0m'

show_usage() {
    echo "meg+ Results Browser"
    echo
    echo "Usage:"
    echo "  ./browse_results.sh [option]"
    echo
    echo "Options:"
    echo "  -s, --summary     Show quick summary"
    echo "  -2, --200         Show all 200 OK responses"
    echo "  -3, --3xx         Show redirects (3xx)"
    echo "  -4, --4xx         Show access restricted (401/403)"
    echo "  -5, --5xx         Show server errors"
    echo "  -d, --domains     List scanned domains"
    echo "  -h, --help        Show this help"
    echo
    echo "Examples:"
    echo "  ./browse_results.sh -s        # Quick summary"
    echo "  ./browse_results.sh -2        # All 200 responses"
    echo "  ./browse_results.sh -d        # List domains"
}

log() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "info")
            printf "${GREEN}[+]${END} %s\n" "$message"
            ;;
        "warn")
            printf "${YELLOW}[!]${END} %s\n" "$message"
            ;;
        "error")
            printf "${RED}[-]${END} %s\n" "$message"
            ;;
        "note")
            printf "${YELLOW}[i]${END} %s\n" "$message"
            ;;
    esac
}

check_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        log "error" "No output directory found at $OUTPUT_DIR"
        exit 1
    fi
}

show_summary() {
    check_output_dir
    
    log "info" "meg+ Results Summary"
    echo
    
    # Count directories (scanned domains)
    local domain_count=$(find "$OUTPUT_DIR" -maxdepth 1 -type d ! -path "$OUTPUT_DIR" | wc -l)
    log "note" "Scanned domains: $domain_count"
    
    # Count different response types
    local count_200=$(grep -r "200 OK" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    local count_3xx=$(grep -rE "30[1-8]" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    local count_4xx=$(grep -rE "40[13]" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    local count_5xx=$(grep -rE "50[0-9]" "$OUTPUT_DIR/" 2>/dev/null | wc -l)
    
    echo "Response Summary:"
    echo -e "  ${GREEN}2xx (Success):${END}        $count_200"
    echo -e "  ${YELLOW}3xx (Redirects):${END}      $count_3xx"
    echo -e "  ${CYAN}4xx (Client Error):${END}   $count_4xx"
    echo -e "  ${RED}5xx (Server Error):${END}   $count_5xx"
    echo
    
    log "info" "Use other options to explore specific results"
}

show_200_responses() {
    check_output_dir
    
    log "info" "All 200 OK Responses:"
    echo
    
    grep -r "200 OK" "$OUTPUT_DIR/" 2>/dev/null | while IFS=':' read -r file rest; do
        domain=$(basename "$(dirname "$file")")
        printf "${GREEN}%-20s${END} %s\n" "$domain" "$rest"
    done | sort
}

show_redirects() {
    check_output_dir
    
    log "info" "Redirect Responses (3xx):"
    echo
    
    grep -rE "30[1-8]" "$OUTPUT_DIR/" 2>/dev/null | while IFS=':' read -r file rest; do
        domain=$(basename "$(dirname "$file")")
        printf "${YELLOW}%-20s${END} %s\n" "$domain" "$rest"
    done | sort | head -20
}

show_4xx() {
    check_output_dir
    
    log "info" "Access Restricted (401/403):"
    echo
    
    grep -rE "40[13]" "$OUTPUT_DIR/" 2>/dev/null | while IFS=':' read -r file rest; do
        domain=$(basename "$(dirname "$file")")
        printf "${CYAN}%-20s${END} %s\n" "$domain" "$rest"
    done | sort | head -20
}

show_5xx() {
    check_output_dir
    
    log "info" "Server Errors (5xx):"
    echo
    
    grep -rE "50[0-9]" "$OUTPUT_DIR/" 2>/dev/null | while IFS=':' read -r file rest; do
        domain=$(basename "$(dirname "$file")")
        printf "${RED}%-20s${END} %s\n" "$domain" "$rest"
    done | sort | head -20
}

list_domains() {
    check_output_dir
    
    log "info" "Scanned Domains:"
    echo
    
    find "$OUTPUT_DIR" -maxdepth 1 -type d ! -path "$OUTPUT_DIR" | while read -r domain_dir; do
        domain=$(basename "$domain_dir")
        file_count=$(find "$domain_dir" -type f | wc -l)
        printf "${GREEN}%-30s${END} (%d files)\n" "$domain" "$file_count"
    done | sort
}

# Main function
main() {
    case "${1:-}" in
        "" | "-h" | "--help")
            show_usage
            ;;
        "-s" | "--summary")
            show_summary
            ;;
        "-2" | "--200")
            show_200_responses
            ;;
        "-3" | "--3xx")
            show_redirects
            ;;
        "-4" | "--4xx")
            show_4xx
            ;;
        "-5" | "--5xx")
            show_5xx
            ;;
        "-d" | "--domains")
            list_domains
            ;;
        *)
            log "error" "Unknown option: $1"
            show_usage
            ;;
    esac
}

main "$@"

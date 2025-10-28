#!/bin/bash

# Script to display X.509v3 extension characteristics of certificates in keystores
# Usage: ./show-cert-extensions.sh [keystore_file] [alias]

# Function to display usage
usage() {
    echo "Usage: $0 [keystore_file] [alias]"
    echo ""
    echo "Parameters:"
    echo "  keystore_file  Path to the JKS keystore file (optional, defaults to all keystores in current directory)"
    echo "  alias          Certificate alias to examine (optional, shows all aliases if not specified)"
    echo ""
    echo "Examples:"
    echo "  $0                          # Show extensions for all certificates in all keystores"
    echo "  $0 client.jks              # Show extensions for all certificates in client.jks"
    echo "  $0 server.jks myserver     # Show extensions for 'myserver' alias in server.jks"
    echo ""
    echo "Available keystores in current directory:"
    ls -1 *.jks 2>/dev/null | sed 's/^/  /'
    exit 1
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Default keystore password (commonly used in development)
KEYSTORE_PASSWORD="changeit"

# Function to print colored header
print_header() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================================${NC}"
}

# Function to print section header
print_section() {
    echo -e "\n${YELLOW}--- $1 ---${NC}"
}

# Function to display certificate extensions for a specific alias
show_certificate_extensions() {
    local keystore_file="$1"
    local alias="$2"
    
    echo -e "\n${GREEN}Certificate Extensions for alias '${alias}' in ${keystore_file}:${NC}"
    echo -e "${BLUE}Keystore:${NC} $keystore_file"
    echo -e "${BLUE}Alias:${NC} $alias"
    
    # Get certificate details
    cert_info=$(keytool -list -v -keystore "$keystore_file" -alias "$alias" -storepass "$KEYSTORE_PASSWORD" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Could not read certificate for alias '$alias' from keystore '$keystore_file'${NC}"
        return 1
    fi
    
    # Extract basic certificate information
    print_section "Basic Certificate Information"
    echo "$cert_info" | grep -E "(Owner:|Issuer:|Serial number:|Valid from:|Certificate fingerprints:)" | while IFS= read -r line; do
        if [[ $line == *"Owner:"* ]]; then
            echo -e "${BLUE}Subject:${NC} ${line#*Owner: }"
        elif [[ $line == *"Issuer:"* ]]; then
            echo -e "${BLUE}Issuer:${NC} ${line#*Issuer: }"
        elif [[ $line == *"Serial number:"* ]]; then
            echo -e "${BLUE}Serial:${NC} ${line#*Serial number: }"
        elif [[ $line == *"Valid from:"* ]]; then
            echo -e "${BLUE}Validity:${NC} ${line#*Valid from: }"
        fi
    done
    
    # Extract and display X.509v3 extensions
    print_section "X.509v3 Extensions"
    
    # Look for extensions section
    extensions_found=false
    in_extensions=false
    
    echo "$cert_info" | while IFS= read -r line; do
        # Check if we're entering the extensions section
        if [[ $line == *"Extensions:"* ]]; then
            in_extensions=true
            extensions_found=true
            continue
        fi
        
        # If we're in extensions section, process the line
        if [ "$in_extensions" = true ]; then
            # Check if we've reached the end of extensions (empty line or next section)
            if [[ -z "$line" ]] || [[ $line == *"Signature algorithm"* ]]; then
                break
            fi
            
            # Process extension lines
            if [[ $line == *"#"* ]]; then
                # This is an extension header
                extension_name=$(echo "$line" | sed 's/^[[:space:]]*#[0-9]*: //' | sed 's/:.*$//')
                extension_critical=""
                if [[ $line == *"critical"* ]]; then
                    extension_critical=" ${RED}(CRITICAL)${NC}"
                fi
                echo -e "${PURPLE}${extension_name}${NC}${extension_critical}"
            else
                # This is extension content
                if [[ ! -z "$line" ]]; then
                    echo "  $line"
                fi
            fi
        fi
    done
    
    # If no extensions were found, check if this is due to an older keytool version
    if [ "$extensions_found" = false ]; then
        echo -e "${YELLOW}No X.509v3 extensions found in the output.${NC}"
        echo -e "${YELLOW}This might be due to an older version of keytool or the certificate may not have extensions.${NC}"
        
        # Try alternative approach - export certificate and use openssl
        print_section "Alternative Analysis using OpenSSL"
        temp_cert="/tmp/temp_cert_${alias}.pem"
        
        # Export certificate to PEM format
        keytool -exportcert -keystore "$keystore_file" -alias "$alias" -storepass "$KEYSTORE_PASSWORD" -rfc > "$temp_cert" 2>/dev/null
        
        if [ $? -eq 0 ] && command -v openssl >/dev/null 2>&1; then
            echo -e "${BLUE}Using OpenSSL to analyze certificate extensions:${NC}"
            openssl x509 -in "$temp_cert" -text -noout | grep -A 20 "X509v3 extensions:" | sed 's/^/  /'
            rm -f "$temp_cert"
        else
            echo -e "${YELLOW}OpenSSL not available or certificate export failed.${NC}"
        fi
    fi
}

# Function to list all aliases in a keystore
list_aliases() {
    local keystore_file="$1"
    keytool -list -keystore "$keystore_file" -storepass "$KEYSTORE_PASSWORD" 2>/dev/null | grep -E "^[a-zA-Z0-9].*," | cut -d',' -f1
}

# Function to process a single keystore
process_keystore() {
    local keystore_file="$1"
    local specific_alias="$2"
    
    if [ ! -f "$keystore_file" ]; then
        echo -e "${RED}Error: Keystore file '$keystore_file' not found.${NC}"
        return 1
    fi
    
    print_header "Analyzing Keystore: $keystore_file"
    
    if [ -n "$specific_alias" ]; then
        # Show specific alias
        show_certificate_extensions "$keystore_file" "$specific_alias"
    else
        # Show all aliases
        aliases=$(list_aliases "$keystore_file")
        if [ -z "$aliases" ]; then
            echo -e "${YELLOW}No certificates found in keystore '$keystore_file' or incorrect password.${NC}"
            return 1
        fi
        
        echo -e "${BLUE}Found aliases:${NC} $(echo "$aliases" | tr '\n' ' ')"
        
        for alias in $aliases; do
            show_certificate_extensions "$keystore_file" "$alias"
        done
    fi
}

# Main script logic
main() {
    # Check if help is requested
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        usage
    fi
    
    # Check if keytool is available
    if ! command -v keytool >/dev/null 2>&1; then
        echo -e "${RED}Error: 'keytool' command not found. Please ensure Java is installed and in your PATH.${NC}"
        exit 1
    fi
    
    local keystore_file="$1"
    local alias="$2"
    
    if [ -z "$keystore_file" ]; then
        # No keystore specified, process all .jks files in current directory
        jks_files=$(ls *.jks 2>/dev/null)
        if [ -z "$jks_files" ]; then
            echo -e "${RED}Error: No .jks files found in current directory.${NC}"
            echo "Available files:"
            ls -la
            exit 1
        fi
        
        for jks_file in $jks_files; do
            process_keystore "$jks_file"
        done
    else
        # Process specific keystore
        process_keystore "$keystore_file" "$alias"
    fi
}

# Run main function with all arguments
main "$@"
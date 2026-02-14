#!/bin/bash

# Script to check for CNAME entries in subdomains
# Usage: ./check_cname.sh -f <input_file> -o <output_file>

INPUT_FILE=""
OUTPUT_FILE=""

# Parse command-line arguments
while getopts "f:o:h" opt; do
    case $opt in
        f) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h)
            echo "Usage: ./check_cname.sh -f <input_file> -o <output_file>"
            echo ""
            echo "Options:"
            echo "  -f  Input file containing subdomains (required)"
            echo "  -o  Output file for CNAME results (required)"
            echo "  -h  Display this help message"
            exit 0
            ;;
        *)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# Check if arguments are provided
if [ -z "$INPUT_FILE" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Error: Both -f and -o flags are required!"
    echo "Usage: ./check_cname.sh -f <input_file> -o <output_file>"
    exit 1
fi

# Clear output file if it exists
> "$OUTPUT_FILE"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found!"
    exit 1
fi

echo "Checking for CNAME entries..."

while IFS= read -r domain; do
    # Skip empty lines
    [ -z "$domain" ] && continue

    # Query for CNAME record
    cname=$(dig +short CNAME "$domain" 2>/dev/null)

    # If CNAME entry exists (non-empty result)
    if [ -n "$cname" ]; then
        echo "$domain -> $cname" | tee -a "$OUTPUT_FILE"
    fi
done < "$INPUT_FILE"

echo "Done! Results saved to $OUTPUT_FILE"

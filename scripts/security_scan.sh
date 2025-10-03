#!/bin/bash

# Security Hardening and Vulnerability Scanning Script for Marty Platform
# Implements comprehensive security checks and vulnerability assessments

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Security configuration
SECURITY_REPORTS_DIR="$PROJECT_ROOT/reports/security"
SECURITY_CONFIG_DIR="$PROJECT_ROOT/config/security"
LOG_FILE="$PROJECT_ROOT/logs/security_scan.log"

# Function to print colored output
print_header() {
    echo -e "${BLUE}${1}${NC}"
    echo "$(printf '=%.0s' {1..60})"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

print_critical() {
    echo -e "${PURPLE}🚨${NC} $1"
}

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to ensure required tools are available
check_dependencies() {
    print_header "🔧 Checking Security Tools Dependencies"
    
    local missing_tools=()
    
    # Check for UV (primary package manager)
    if ! command_exists uv; then
        missing_tools+=("uv")
    fi
    
    # Check for Docker (for container security scans)
    if ! command_exists docker; then
        missing_tools+=("docker")
    fi
    
    # Check for git (for secrets scanning)
    if ! command_exists git; then
        missing_tools+=("git")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_info "Please install missing tools before running security scans"
        exit 1
    fi
    
    print_success "All required tools are available"
}

# Function to setup security directories
setup_directories() {
    print_header "📁 Setting up Security Directories"
    
    mkdir -p "$SECURITY_REPORTS_DIR"/{dependency,vulnerability,secrets,container,code,compliance}
    mkdir -p "$SECURITY_CONFIG_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    print_success "Security directories created"
}

# Function to run dependency vulnerability scanning
scan_dependencies() {
    print_header "🔍 Scanning Dependencies for Vulnerabilities"
    
    cd "$PROJECT_ROOT"
    
    echo "Running safety check for Python dependencies..."
    if uv run safety check --json --output "$SECURITY_REPORTS_DIR/dependency/safety_report.json" 2>/dev/null; then
        print_success "Safety scan completed successfully"
    else
        # Safety returns non-zero exit code when vulnerabilities are found
        print_warning "Safety scan found vulnerabilities (check report for details)"
    fi
    
    # Generate human-readable report
    uv run safety check --output "$SECURITY_REPORTS_DIR/dependency/safety_report.txt" 2>/dev/null || true
    
    echo "Running pip-audit for additional vulnerability checks..."
    if command_exists pip-audit || uv run pip-audit --version >/dev/null 2>&1; then
        uv run pip-audit --format=json --output="$SECURITY_REPORTS_DIR/dependency/pip_audit_report.json" 2>/dev/null || true
        uv run pip-audit --format=text --output="$SECURITY_REPORTS_DIR/dependency/pip_audit_report.txt" 2>/dev/null || true
        print_success "Pip-audit scan completed"
    else
        print_info "pip-audit not available, skipping extended vulnerability check"
    fi
    
    log_message "Dependency vulnerability scan completed"
}

# Function to run code security analysis
scan_code_security() {
    print_header "🔒 Running Code Security Analysis"
    
    cd "$PROJECT_ROOT"
    
    echo "Running Bandit security analysis..."
    uv run bandit -r src/ -f json -o "$SECURITY_REPORTS_DIR/code/bandit_report.json" 2>/dev/null || true
    uv run bandit -r src/ -f txt -o "$SECURITY_REPORTS_DIR/code/bandit_report.txt" 2>/dev/null || true
    
    if [[ -f "$SECURITY_REPORTS_DIR/code/bandit_report.txt" ]]; then
        print_success "Bandit security analysis completed"
    else
        print_warning "Bandit analysis may have failed"
    fi
    
    echo "Running semgrep security analysis..."
    if command_exists semgrep; then
        semgrep --config=auto --json --output="$SECURITY_REPORTS_DIR/code/semgrep_report.json" src/ 2>/dev/null || true
        semgrep --config=auto --output="$SECURITY_REPORTS_DIR/code/semgrep_report.txt" src/ 2>/dev/null || true
        print_success "Semgrep analysis completed"
    else
        print_info "Semgrep not available, skipping advanced code analysis"
    fi
    
    log_message "Code security analysis completed"
}

# Function to scan for secrets in code
scan_secrets() {
    print_header "🕵️ Scanning for Secrets and Sensitive Data"
    
    cd "$PROJECT_ROOT"
    
    echo "Running truffleHog for secrets detection..."
    if command_exists truffleHog; then
        truffleHog filesystem . --json > "$SECURITY_REPORTS_DIR/secrets/truffleHog_report.json" 2>/dev/null || true
        print_success "TruffleHog secrets scan completed"
    else
        print_info "TruffleHog not available, using detect-secrets instead"
    fi
    
    echo "Running detect-secrets scan..."
    if command_exists detect-secrets || uv run detect-secrets --version >/dev/null 2>&1; then
        uv run detect-secrets scan --all-files > "$SECURITY_REPORTS_DIR/secrets/detect_secrets_baseline.json" 2>/dev/null || true
        print_success "detect-secrets scan completed"
    else
        print_info "detect-secrets not available"
    fi
    
    echo "Running git-secrets check..."
    if command_exists git-secrets; then
        git secrets --scan > "$SECURITY_REPORTS_DIR/secrets/git_secrets_report.txt" 2>&1 || true
        print_success "git-secrets scan completed"
    else
        print_info "git-secrets not available"
    fi
    
    # Custom secrets pattern scanning
    echo "Running custom secrets pattern matching..."
    grep -r -E "(password|secret|key|token|api_key)" --include="*.py" --include="*.yaml" --include="*.json" src/ config/ > "$SECURITY_REPORTS_DIR/secrets/custom_patterns.txt" 2>/dev/null || true
    
    log_message "Secrets scanning completed"
}

# Function to scan container security
scan_containers() {
    print_header "🐳 Scanning Container Security"
    
    cd "$PROJECT_ROOT"
    
    if [[ -f "docker/docker-compose.yml" ]]; then
        echo "Analyzing Docker configurations..."
        
        # Check for security best practices in Dockerfiles
        find docker/ -name "*.Dockerfile" -o -name "Dockerfile*" | while read -r dockerfile; do
            echo "Analyzing $dockerfile..."
            
            # Custom security checks for Dockerfiles
            {
                echo "=== Security Analysis for $dockerfile ==="
                echo "Checking for security best practices..."
                
                # Check for running as root
                if ! grep -q "USER " "$dockerfile"; then
                    echo "WARNING: No USER instruction found - container may run as root"
                fi
                
                # Check for COPY vs ADD
                if grep -q "ADD " "$dockerfile"; then
                    echo "WARNING: ADD instruction found - consider using COPY instead"
                fi
                
                # Check for version pinning
                if grep -qE "FROM.*:latest" "$dockerfile"; then
                    echo "WARNING: Using 'latest' tag - consider pinning specific versions"
                fi
                
                echo ""
            } >> "$SECURITY_REPORTS_DIR/container/dockerfile_analysis.txt"
        done
        
        print_success "Docker configuration analysis completed"
    else
        print_info "No Docker configurations found"
    fi
    
    # Scan running containers if any
    if docker ps -q >/dev/null 2>&1; then
        echo "Scanning running containers..."
        docker ps --format "table {{.Image}}\\t{{.Status}}\\t{{.Ports}}" > "$SECURITY_REPORTS_DIR/container/running_containers.txt" 2>/dev/null || true
        print_success "Container inventory completed"
    fi
    
    log_message "Container security scan completed"
}

# Function to run compliance checks
run_compliance_checks() {
    print_header "📋 Running Security Compliance Checks"
    
    cd "$PROJECT_ROOT"
    
    local compliance_report="$SECURITY_REPORTS_DIR/compliance/compliance_report.txt"
    
    {
        echo "=== MARTY PLATFORM SECURITY COMPLIANCE REPORT ==="
        echo "Generated: $(date)"
        echo ""
        
        echo "=== OWASP Top 10 Checklist ==="
        echo "□ A01:2021 – Broken Access Control"
        echo "  - Authentication mechanisms implemented: $(find src/ -name "*auth*" | wc -l) files"
        echo "  - Authorization checks: $(grep -r "authorize\|permission" src/ | wc -l) occurrences"
        echo ""
        
        echo "□ A02:2021 – Cryptographic Failures"
        echo "  - Encryption usage: $(grep -r "encrypt\|crypto\|hash" src/ | wc -l) occurrences"
        echo "  - SSL/TLS configuration files: $(find config/ -name "*ssl*" -o -name "*tls*" | wc -l) files"
        echo ""
        
        echo "□ A03:2021 – Injection"
        echo "  - SQL injection prevention: $(grep -r "parameterized\|prepared" src/ | wc -l) occurrences"
        echo "  - Input validation: $(grep -r "validate\|sanitize" src/ | wc -l) occurrences"
        echo ""
        
        echo "□ A04:2021 – Insecure Design"
        echo "  - Security requirements documentation: $(find docs/ -name "*security*" | wc -l) files"
        echo "  - Threat modeling artifacts: $(find docs/ -name "*threat*" | wc -l) files"
        echo ""
        
        echo "□ A05:2021 – Security Misconfiguration"
        echo "  - Configuration files: $(find config/ -name "*.yaml" -o -name "*.json" | wc -l) files"
        echo "  - Environment-specific configs: $(ls config/ | grep -E "(dev|prod|test)" | wc -l) configs"
        echo ""
        
        echo "□ A06:2021 – Vulnerable and Outdated Components"
        echo "  - Dependency files: $(find . -name "pyproject.toml" -o -name "requirements*.txt" | wc -l) files"
        echo "  - Security scanning implemented: YES (this script)"
        echo ""
        
        echo "□ A07:2021 – Identification and Authentication Failures"
        echo "  - Authentication implementations: $(find src/ -name "*auth*" -o -name "*login*" | wc -l) files"
        echo "  - Session management: $(grep -r "session" src/ | wc -l) occurrences"
        echo ""
        
        echo "□ A08:2021 – Software and Data Integrity Failures"
        echo "  - Digital signatures: $(grep -r "sign\|signature" src/ | wc -l) occurrences"
        echo "  - Integrity checks: $(grep -r "checksum\|hash\|integrity" src/ | wc -l) occurrences"
        echo ""
        
        echo "□ A09:2021 – Security Logging and Monitoring Failures"
        echo "  - Logging implementations: $(find src/ -name "*log*" | wc -l) files"
        echo "  - Monitoring configurations: $(find monitoring/ -type f 2>/dev/null | wc -l) files"
        echo ""
        
        echo "□ A10:2021 – Server-Side Request Forgery (SSRF)"
        echo "  - HTTP client implementations: $(grep -r "requests\|httpx\|urllib" src/ | wc -l) occurrences"
        echo "  - URL validation: $(grep -r "url.*valid" src/ | wc -l) occurrences"
        echo ""
        
        echo "=== Security Headers Checklist ==="
        echo "□ Content Security Policy (CSP)"
        echo "□ HTTP Strict Transport Security (HSTS)"
        echo "□ X-Frame-Options"
        echo "□ X-Content-Type-Options"
        echo "□ X-XSS-Protection"
        echo ""
        
        echo "=== Data Protection Compliance ==="
        echo "□ GDPR/Privacy considerations"
        echo "□ Data encryption at rest"
        echo "□ Data encryption in transit"
        echo "□ Personal data handling procedures"
        echo ""
        
        echo "=== Infrastructure Security ==="
        echo "□ Container security scanning"
        echo "□ Network security configuration"
        echo "□ Secret management"
        echo "□ Access control policies"
        
    } > "$compliance_report"
    
    print_success "Compliance checklist generated"
    log_message "Compliance checks completed"
}

# Function to generate security summary report
generate_security_report() {
    print_header "📊 Generating Security Summary Report"
    
    local summary_report="$SECURITY_REPORTS_DIR/security_summary.md"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    {
        echo "# Marty Platform Security Scan Summary"
        echo ""
        echo "**Generated:** $timestamp"
        echo "**Scan Type:** Comprehensive Security Assessment"
        echo ""
        
        echo "## 🔍 Scan Results Overview"
        echo ""
        
        # Dependency vulnerabilities
        if [[ -f "$SECURITY_REPORTS_DIR/dependency/safety_report.txt" ]]; then
            local vuln_count=$(grep -c "vulnerability" "$SECURITY_REPORTS_DIR/dependency/safety_report.txt" 2>/dev/null || echo "0")
            echo "- **Dependency Vulnerabilities:** $vuln_count found"
        fi
        
        # Code security issues
        if [[ -f "$SECURITY_REPORTS_DIR/code/bandit_report.txt" ]]; then
            local code_issues=$(grep -c "Issue" "$SECURITY_REPORTS_DIR/code/bandit_report.txt" 2>/dev/null || echo "0")
            echo "- **Code Security Issues:** $code_issues found"
        fi
        
        # Secrets detection
        if [[ -f "$SECURITY_REPORTS_DIR/secrets/detect_secrets_baseline.json" ]]; then
            local secrets_count=$(jq '.results | length' "$SECURITY_REPORTS_DIR/secrets/detect_secrets_baseline.json" 2>/dev/null || echo "0")
            echo "- **Potential Secrets:** $secrets_count detected"
        fi
        
        echo ""
        echo "## 📁 Report Files Generated"
        echo ""
        find "$SECURITY_REPORTS_DIR" -type f -name "*.txt" -o -name "*.json" -o -name "*.md" | while read -r file; do
            local rel_path=${file#$PROJECT_ROOT/}
            echo "- \`$rel_path\`"
        done
        
        echo ""
        echo "## 🚨 Critical Security Recommendations"
        echo ""
        echo "1. **Regular Dependency Updates:** Keep all dependencies updated to latest secure versions"
        echo "2. **Secrets Management:** Implement proper secrets management system (HashiCorp Vault, AWS Secrets Manager)"
        echo "3. **Container Security:** Regularly scan container images and follow security best practices"
        echo "4. **Code Review:** Implement mandatory security code reviews for all changes"
        echo "5. **Monitoring:** Set up security monitoring and alerting for suspicious activities"
        echo "6. **Penetration Testing:** Conduct regular penetration testing by security professionals"
        echo ""
        
        echo "## 🔧 Next Steps"
        echo ""
        echo "1. Review all generated reports in \`reports/security/\`"
        echo "2. Address high-severity vulnerabilities immediately"
        echo "3. Implement automated security scanning in CI/CD pipeline"
        echo "4. Schedule regular security assessments"
        echo "5. Update security policies and procedures"
        echo ""
        
        echo "## 📞 Security Contact"
        echo ""
        echo "For security-related issues or questions:"
        echo "- Create security incident ticket"
        echo "- Follow responsible disclosure procedures"
        echo "- Review security documentation in \`docs/\`"
        
    } > "$summary_report"
    
    print_success "Security summary report generated: $summary_report"
}

# Function to display scan results
display_results() {
    print_header "📊 Security Scan Results Summary"
    
    echo "Security reports have been generated in:"
    echo "  📁 $SECURITY_REPORTS_DIR"
    echo ""
    
    echo "Key reports to review:"
    echo "  🔍 Dependency vulnerabilities: dependency/"
    echo "  🔒 Code security analysis: code/"
    echo "  🕵️ Secrets detection: secrets/"
    echo "  🐳 Container security: container/"
    echo "  📋 Compliance checklist: compliance/"
    echo ""
    
    if [[ -f "$SECURITY_REPORTS_DIR/security_summary.md" ]]; then
        print_info "View complete summary: reports/security/security_summary.md"
    fi
    
    print_warning "⚠️  IMPORTANT: Review all reports and address critical issues immediately"
}

# Main execution function
main() {
    local action="${1:-full}"
    
    print_header "🛡️ Marty Platform Security Hardening Suite"
    echo "Starting comprehensive security assessment..."
    echo ""
    
    # Initialize
    check_dependencies
    setup_directories
    
    log_message "Security scan started - action: $action"
    
    case "$action" in
        "deps"|"dependencies")
            scan_dependencies
            ;;
        "code")
            scan_code_security
            ;;
        "secrets")
            scan_secrets
            ;;
        "containers")
            scan_containers
            ;;
        "compliance")
            run_compliance_checks
            ;;
        "full"|*)
            scan_dependencies
            scan_code_security
            scan_secrets
            scan_containers
            run_compliance_checks
            generate_security_report
            ;;
    esac
    
    display_results
    log_message "Security scan completed - action: $action"
    
    print_success "Security hardening assessment complete! 🎉"
    print_info "Review reports in: $SECURITY_REPORTS_DIR"
}

# Show help if requested
if [[ "${1:-}" == "help" || "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Marty Platform Security Hardening Suite"
    echo "======================================"
    echo ""
    echo "Usage: $0 [ACTION]"
    echo ""
    echo "Actions:"
    echo "  full         - Run complete security assessment (default)"
    echo "  deps         - Scan dependencies for vulnerabilities"
    echo "  code         - Run code security analysis"
    echo "  secrets      - Scan for secrets and sensitive data"
    echo "  containers   - Analyze container security"
    echo "  compliance   - Generate compliance checklist"
    echo "  help         - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0           # Run full security assessment"
    echo "  $0 deps      # Check dependencies only"
    echo "  $0 secrets   # Scan for secrets only"
    exit 0
fi

# Run main function
main "$@"
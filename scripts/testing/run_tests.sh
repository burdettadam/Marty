#!/usr/bin/env bash
# Test Runner Script for Marty Passport Verification System
# Provides convenient commands for running different test categories

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}$1${NC}"
    echo "==========================================="
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Help function
show_help() {
    echo -e "${PURPLE}Marty Passport Verification System - Test Runner${NC}"
    echo
    echo "Usage: ./run_tests.sh [COMMAND] [OPTIONS]"
    echo
    echo "Commands:"
    echo "  all                 Run all tests (unit, integration, performance)"
    echo "  unit                Run only unit tests (phase 2 + phase 3)"
    echo "  integration         Run only integration tests"
    echo "  performance         Run performance tests"
    echo "  phase2              Run all Phase 2 RFID tests"
    echo "  phase3              Run all Phase 3 Security tests"
    echo "  coverage            Run tests with coverage report"
    echo "  quick               Run fast tests only (no performance/slow tests)"
    echo "  security            Run security-focused tests"
    echo "  clean               Clean test artifacts and cache"
    echo "  setup               Install test dependencies"
    echo
    echo "Options:"
    echo "  -v, --verbose       Verbose output"
    echo "  -f, --fail-fast     Stop on first failure"
    echo "  -k PATTERN          Run tests matching pattern"
    echo "  --parallel          Run tests in parallel (requires pytest-xdist)"
    echo "  --html              Generate HTML test report"
    echo
    echo "Examples:"
    echo "  ./run_tests.sh unit -v"
    echo "  ./run_tests.sh phase2 --html"
    echo "  ./run_tests.sh coverage"
    echo "  ./run_tests.sh quick --parallel"
}

# Setup function to install dependencies
setup_test_env() {
    print_header "Setting up test environment"

    print_info "Installing test dependencies..."
    pip install pytest pytest-asyncio pytest-cov pytest-html pytest-xdist coverage

    print_info "Installing development dependencies..."
    pip install ruff mypy black isort bandit

    print_success "Test environment setup complete"
}

# Clean function
clean_test_artifacts() {
    print_header "Cleaning test artifacts"

    # Remove pytest cache
    if [ -d ".pytest_cache" ]; then
        rm -rf .pytest_cache
        print_info "Removed pytest cache"
    fi

    # Remove coverage files
    if [ -f ".coverage" ]; then
        rm -f .coverage
        print_info "Removed coverage data"
    fi

    if [ -d "htmlcov" ]; then
        rm -rf htmlcov
        print_info "Removed HTML coverage report"
    fi

    # Remove test reports
    if [ -d "test-reports" ]; then
        rm -rf test-reports
        print_info "Removed test reports"
    fi

    # Remove Python cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true

    print_success "Cleanup complete"
}

# Parse command line arguments
COMMAND=""
VERBOSE=""
FAIL_FAST=""
PATTERN=""
PARALLEL=""
HTML_REPORT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        all|unit|integration|performance|phase2|phase3|coverage|quick|security|clean|setup)
            COMMAND="$1"
            shift
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        -f|--fail-fast)
            FAIL_FAST="--maxfail=1"
            shift
            ;;
        -k)
            PATTERN="-k $2"
            shift
            shift
            ;;
        --parallel)
            PARALLEL="-n auto"
            shift
            ;;
        --html)
            HTML_REPORT="--html=test-reports/report.html --self-contained-html"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Default to showing help if no command provided
if [[ -z "$COMMAND" ]]; then
    show_help
    exit 0
fi

# Create test reports directory if HTML report requested
if [[ -n "$HTML_REPORT" ]]; then
    mkdir -p test-reports
fi

# Build pytest command with common options
PYTEST_CMD="python -m pytest $VERBOSE $FAIL_FAST $PATTERN $PARALLEL $HTML_REPORT"

# Execute based on command
case $COMMAND in
    setup)
        setup_test_env
        ;;

    clean)
        clean_test_artifacts
        ;;

    all)
        print_header "Running all tests"
        $PYTEST_CMD tests/
        ;;

    unit)
        print_header "Running unit tests"
        $PYTEST_CMD tests/test_phase2_units.py tests/test_phase3_units.py -m "unit or not integration"
        ;;

    integration)
        print_header "Running integration tests"
        $PYTEST_CMD tests/test_phase2_integration.py tests/test_phase3_integration.py -m "integration"
        ;;

    performance)
        print_header "Running performance tests"
        print_warning "Performance tests may take significant time"
        $PYTEST_CMD tests/test_performance_suite.py -m "performance"
        ;;

    phase2)
        print_header "Running Phase 2 RFID tests"
        $PYTEST_CMD tests/test_phase2_units.py tests/test_phase2_integration.py -m "phase2 or rfid"
        ;;

    phase3)
        print_header "Running Phase 3 Security tests"
        $PYTEST_CMD tests/test_phase3_units.py tests/test_phase3_integration.py -m "phase3 or security"
        ;;

    coverage)
        print_header "Running tests with coverage analysis"
        print_info "This will run comprehensive coverage analysis..."

        # Use the comprehensive coverage script
        if [[ -f "generate_test_coverage.py" ]]; then
            python generate_test_coverage.py
        else
            # Fallback to basic coverage
            python -m pytest --cov=src --cov-report=html --cov-report=term-missing --cov-fail-under=75 tests/
            print_info "Coverage report generated in htmlcov/index.html"
        fi
        ;;

    quick)
        print_header "Running quick tests"
        $PYTEST_CMD tests/ -m "not slow and not performance"
        ;;

    security)
        print_header "Running security tests"
        $PYTEST_CMD tests/ -m "security"
        ;;

    *)
        print_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac

# Check exit code and provide feedback
if [[ $? -eq 0 ]]; then
    print_success "Tests completed successfully!"

    if [[ -n "$HTML_REPORT" ]]; then
        print_info "HTML report available at: test-reports/report.html"
    fi
else
    print_error "Tests failed!"
    exit 1
fi

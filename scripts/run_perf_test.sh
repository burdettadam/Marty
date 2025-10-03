#!/bin/bash
# Performance Testing Script for Marty Platform

set -e

echo "🚀 Starting Performance Testing for Marty Platform..."

# Configuration
SERVICE="${1:-pkd_service}"
TEST_TYPE="${2:-load}"
USERS="${3:-10}"
DURATION="${4:-60}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Configuration:${NC}"
echo "  Service: $SERVICE"
echo "  Test Type: $TEST_TYPE"
echo "  Users: $USERS"
echo "  Duration: ${DURATION}s"
echo

# Check if service is running
case $SERVICE in
    "pkd_service")
        PORT=8088
        ;;
    "document_processing")
        PORT=8080
        ;;
    "ui_app")
        PORT=8000
        ;;
    *)
        echo -e "${RED}❌ Unknown service: $SERVICE${NC}"
        echo "Available services: pkd_service, document_processing, ui_app"
        exit 1
        ;;
esac

echo -e "${YELLOW}🔍 Checking if $SERVICE is running on port $PORT...${NC}"
if ! curl -s http://localhost:$PORT > /dev/null; then
    echo -e "${RED}❌ Service $SERVICE is not running on port $PORT${NC}"
    echo "Please start the service first:"
    echo "  make run-$SERVICE"
    exit 1
fi

echo -e "${GREEN}✅ Service $SERVICE is responding${NC}"
echo

# Create reports directory
mkdir -p reports/performance

# Make the performance test script executable
chmod +x scripts/performance_test.py

# Run the performance test
echo -e "${BLUE}🏃 Running $TEST_TYPE test on $SERVICE...${NC}"
uv run python scripts/performance_test.py $TEST_TYPE $SERVICE --users $USERS --duration $DURATION

echo
echo -e "${GREEN}✅ Performance test completed!${NC}"
echo -e "${BLUE}📊 Check the reports/performance/ directory for detailed results${NC}"
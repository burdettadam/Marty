#!/bin/bash
# Performance Testing Script for Marty Platform

set -e

echo "🚀 Starting Performance Testing for Marty Platform..."

# Configuration
SERVICE="${1:-pkd_service}"
TEST_TYPE="${2:-load}"
USERS="${3:-10}"
DURATION="${4:-60}"
OUTPUT_DIR="${5:-reports/performance}"

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
echo "  Output Directory: $OUTPUT_DIR"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if service is running
case $SERVICE in
    "pkd_service")
        PORT=8088
        GRPC_PORT=9088
        ;;
    "trust-svc")
        PORT=8090
        GRPC_PORT=9090
        ;;
    "csca-service")
        PORT=8092
        GRPC_PORT=9092
        ;;
    "passport-engine")
        PORT=8095
        GRPC_PORT=9095
        ;;
    "mdl-engine")
        PORT=8096
        GRPC_PORT=9096
        ;;
    "inspection-system")
        PORT=8094
        GRPC_PORT=9094
        ;;
    "document_processing"|"ui_app")
        PORT=8000
        GRPC_PORT=0  # UI doesn't have gRPC
        ;;
    *)
        echo -e "${RED}❌ Unknown service: $SERVICE${NC}"
        echo "Available services: pkd_service, trust-svc, csca-service, passport-engine, mdl-engine, inspection-system, ui_app"
        exit 1
        ;;
esac

echo -e "${YELLOW}🔍 Checking if $SERVICE is running on port $PORT...${NC}"
if ! curl -s http://localhost:$PORT/health > /dev/null; then
    echo -e "${RED}❌ Service $SERVICE is not running on port $PORT${NC}"
    echo "Please start the service first:"
    case $SERVICE in
        "ui_app")
            echo "  make run-ui"
            ;;
        *)
            echo "  docker-compose up -d $SERVICE"
            ;;
    esac
    exit 1
fi

echo -e "${GREEN}✅ Service $SERVICE is running${NC}"

# Generate timestamp for this test run
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TEST_RUN_ID="${SERVICE}_${TEST_TYPE}_${TIMESTAMP}"

echo -e "${BLUE}🧪 Running performance test...${NC}"

# Run the Python performance test script
python3 scripts/performance_test.py \
    --service="$SERVICE" \
    --test-type="$TEST_TYPE" \
    --users="$USERS" \
    --duration="$DURATION" \
    --output-dir="$OUTPUT_DIR" \
    --test-run-id="$TEST_RUN_ID" \
    --port="$PORT"

# Check if test was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Performance test completed successfully${NC}"
    echo -e "${BLUE}📊 Results saved to: $OUTPUT_DIR/${TEST_RUN_ID}.csv${NC}"

    # Show summary if available
    if [ -f "$OUTPUT_DIR/${TEST_RUN_ID}_summary.json" ]; then
        echo -e "${YELLOW}📈 Test Summary:${NC}"
        python3 -c "
import json
with open('$OUTPUT_DIR/${TEST_RUN_ID}_summary.json', 'r') as f:
    data = json.load(f)
    print(f'  Total Requests: {data.get(\"total_requests\", \"N/A\")}')
    print(f'  Success Rate: {data.get(\"success_rate\", \"N/A\")}%')
    print(f'  Avg Response Time: {data.get(\"avg_response_time\", \"N/A\")}ms')
    print(f'  95th Percentile: {data.get(\"p95_response_time\", \"N/A\")}ms')
    print(f'  Throughput: {data.get(\"throughput\", \"N/A\")} req/s')
"
    fi

    # CI integration - check performance thresholds
    if [ "$CI" = "true" ] || [ "$GITHUB_ACTIONS" = "true" ]; then
        echo -e "${BLUE}🤖 CI Mode - Checking performance thresholds...${NC}"
        python3 scripts/validate_performance_thresholds.py \
            --results-file="$OUTPUT_DIR/${TEST_RUN_ID}.csv" \
            --service="$SERVICE"

        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Performance thresholds not met${NC}"
            exit 1
        fi

        echo -e "${GREEN}✅ Performance thresholds passed${NC}"
    fi

else
    echo -e "${RED}❌ Performance test failed${NC}"
    exit 1
fi

echo -e "${GREEN}🎉 Performance testing completed for $SERVICE${NC}"

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

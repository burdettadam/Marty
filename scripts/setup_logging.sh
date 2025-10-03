#!/bin/bash

# Centralized Logging Setup Script for Marty Platform
# Sets up ELK stack with Filebeat for log aggregation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Setting up Centralized Logging for Marty Platform${NC}"
echo "=================================================="

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_status "Docker is running"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose is not installed. Please install it and try again."
    exit 1
fi

print_status "docker-compose is available"

# Create logs directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/logs"
print_status "Created logs directory"

# Set proper permissions for Filebeat
chmod 644 "$PROJECT_ROOT/docker/logging/filebeat/filebeat.yml"
print_status "Set Filebeat configuration permissions"

echo
echo -e "${BLUE}🚀 Starting ELK Stack...${NC}"

# Start the ELK stack
cd "$PROJECT_ROOT"
docker-compose -f docker/docker-compose.logging.yml up -d

# Wait for services to be ready
echo
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"

# Wait for Elasticsearch
echo "Waiting for Elasticsearch..."
timeout=60
counter=0
while ! curl -s "http://localhost:9200/_cluster/health" > /dev/null; do
    if [ $counter -gt $timeout ]; then
        print_error "Elasticsearch failed to start within $timeout seconds"
        exit 1
    fi
    sleep 2
    counter=$((counter + 2))
    echo -n "."
done
echo
print_status "Elasticsearch is ready"

# Wait for Kibana
echo "Waiting for Kibana..."
counter=0
while ! curl -s "http://localhost:5601/api/status" > /dev/null; do
    if [ $counter -gt $timeout ]; then
        print_error "Kibana failed to start within $timeout seconds"
        exit 1
    fi
    sleep 2
    counter=$((counter + 2))
    echo -n "."
done
echo
print_status "Kibana is ready"

# Create Elasticsearch index templates
echo
echo -e "${BLUE}📊 Setting up Elasticsearch index templates...${NC}"

# Marty logs template
curl -X PUT "localhost:9200/_index_template/marty-logs" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["marty-*"],
    "template": {
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "service_name": { "type": "keyword" },
          "env": { "type": "keyword" },
          "log_level": { "type": "keyword" },
          "platform": { "type": "keyword" },
          "request_id": { "type": "keyword" },
          "user_id": { "type": "keyword" },
          "session_id": { "type": "keyword" },
          "correlation_id": { "type": "keyword" },
          "metric_type": { "type": "keyword" },
          "log_data": {
            "properties": {
              "response_time": { "type": "float" },
              "status_code": { "type": "integer" },
              "method": { "type": "keyword" },
              "endpoint": { "type": "keyword" },
              "event": { "type": "keyword" },
              "success": { "type": "boolean" },
              "error": { "type": "text" },
              "message": { "type": "text" }
            }
          },
          "geoip": {
            "properties": {
              "location": { "type": "geo_point" },
              "country_name": { "type": "keyword" },
              "city_name": { "type": "keyword" }
            }
          }
        }
      },
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "index.lifecycle.name": "marty-logs-policy",
        "index.lifecycle.rollover_alias": "marty-logs"
      }
    }
  }' > /dev/null

print_status "Created Elasticsearch index template"

# Create index lifecycle policy
curl -X PUT "localhost:9200/_ilm/policy/marty-logs-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "actions": {
            "rollover": {
              "max_size": "10GB",
              "max_age": "7d"
            }
          }
        },
        "warm": {
          "min_age": "7d",
          "actions": {
            "allocate": {
              "number_of_replicas": 0
            }
          }
        },
        "delete": {
          "min_age": "30d"
        }
      }
    }
  }' > /dev/null

print_status "Created index lifecycle policy"

echo
echo -e "${GREEN}🎉 Centralized Logging Setup Complete!${NC}"
echo "======================================"
echo
echo "Services are now running:"
echo -e "  • Elasticsearch: ${BLUE}http://localhost:9200${NC}"
echo -e "  • Kibana:        ${BLUE}http://localhost:5601${NC}"
echo -e "  • Logstash:      ${BLUE}localhost:5044 (Beats), localhost:5000 (TCP)${NC}"
echo
echo "To view logs:"
echo "  1. Open Kibana at http://localhost:5601"
echo "  2. Go to Management > Stack Management > Index Management"
echo "  3. Create index patterns for: marty-*, marty-performance-*, marty-security-*, marty-business-*"
echo "  4. Go to Analytics > Discover to view and search logs"
echo
echo "To stop the logging stack:"
echo "  docker-compose -f docker/docker-compose.logging.yml down"
echo
echo "To view service logs:"
echo "  docker-compose -f docker/docker-compose.logging.yml logs -f [service-name]"
echo

# Create sample log entry to test the pipeline
echo -e "${BLUE}📝 Creating sample log entry...${NC}"
python3 -c "
import sys
sys.path.append('src')
from marty_common.logging.structured_logging import setup_logging_for_service

logger_config = setup_logging_for_service('test_service', environment='development')
logger = logger_config.get_logger()

logger.info('Centralized logging setup complete', 
           setup_version='1.0.0', 
           elk_stack='enabled',
           test_entry=True)
"

print_status "Created sample log entry"

echo
echo -e "${GREEN}✅ Setup complete! Check Kibana for your logs.${NC}"
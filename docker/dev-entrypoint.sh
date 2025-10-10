#!/bin/bash
set -e

# Development entrypoint for Marty MMF Plugin
echo "🚀 Starting Marty MMF Plugin in development mode..."

# Set up development environment
export PYTHONPATH="/app/src:$PYTHONPATH"
export MARTY_ENV="development"

# Show environment info
echo "📋 Environment Information:"
echo "  Python: $(python --version)"
echo "  Working Directory: $(pwd)"
echo "  Plugin Path: $PYTHONPATH"
echo "  Environment: $MARTY_ENV"
echo ""

# Health check
echo "🔍 Plugin Health Check:"
python -c "
from src.mmf_plugin import MartyPlugin
try:
    plugin = MartyPlugin()
    services = plugin.get_services()
    print(f'  ✅ Plugin initialized successfully')
    print(f'  📦 Available services: {len(services)}')
    for service_name in services:
        print(f'    - {service_name}')
except Exception as e:
    print(f'  ❌ Plugin initialization failed: {e}')
    exit(1)
"
echo ""

# Run any pre-startup commands for development
if [ -f "/app/dev-setup.sh" ]; then
    echo "🛠️  Running development setup..."
    bash /app/dev-setup.sh
fi

# Execute the main command
echo "🏃 Executing: $@"
exec "$@"
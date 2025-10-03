#!/bin/bash
# API Documentation Generator Script for Marty Platform

set -e

echo "🚀 Generating API Documentation for Marty Platform..."

# Change to project root
cd "$(dirname "$0")/.."

# Ensure we have required dependencies
echo "📦 Installing documentation dependencies..."
uv add --dev pyyaml

# Make the generator script executable
chmod +x scripts/generate_api_docs.py

# Run the documentation generator
echo "📖 Running API documentation generator..."
uv run python scripts/generate_simple_docs.py

# Check if documentation was generated successfully
if [ -f "docs/api/index.html" ]; then
    echo "✅ API documentation generated successfully!"
    echo "📖 Open docs/api/index.html in your browser to view the documentation"
    echo "🌐 Or run: open docs/api/index.html"
else
    echo "❌ Documentation generation failed"
    exit 1
fi
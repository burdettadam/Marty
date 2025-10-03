#!/bin/bash

# Devcontainer setup script for Marty Platform
# Runs when the devcontainer is first created

set -e

echo "🚀 Setting up Marty Platform development environment..."

# Update package lists
apt-get update

# Install additional development tools
apt-get install -y \
    build-essential \
    curl \
    wget \
    unzip \
    tree \
    htop \
    jq \
    shellcheck \
    postgresql-client

# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"

# Create necessary directories
mkdir -p /workspace/logs
mkdir -p /workspace/reports/coverage
mkdir -p /workspace/reports/performance
mkdir -p /workspace/reports/security

# Set up Python environment
cd /workspace
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg

# Install Playwright browsers
uv run playwright install

# Set permissions
chown -R vscode:vscode /workspace/logs
chown -R vscode:vscode /workspace/reports

echo "✅ Devcontainer setup complete!"
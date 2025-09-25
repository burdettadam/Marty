#!/bin/bash
# Setup script for OpenXPKI integration with Marty

# Create necessary directories
echo "Creating directories for OpenXPKI..."
mkdir -p data/openxpki/config
mkdir -p data/openxpki/tls
mkdir -p data/openxpki/ca
mkdir -p data/openxpki/logs
mkdir -p data/openxpki/db
mkdir -p data/trust/openxpki_sync

# Start OpenXPKI using Docker Compose
echo "Starting OpenXPKI services..."
docker-compose -f docker-compose.openxpki.yml up -d

echo "Waiting for OpenXPKI to initialize (30 seconds)..."
sleep 30

# Display connection information
echo -e "\n=== OpenXPKI Setup Complete ==="
echo "Web UI: https://localhost:8443/openxpki/"
echo "API Endpoint: https://localhost:8443/api/v2"
echo "Username: pkiadmin"
echo "Password: secret (change this in production!)"
echo -e "\nUpdate your development.yaml with these settings:\n"
echo "openxpki:"
echo "  base_url: \"https://localhost:8443/api/v2\""
echo "  username: \"pkiadmin\""
echo "  password: \"secret\""
echo "  realm: \"marty\""
echo -e "\n=== Important Notes ==="
echo "1. You may need to accept the self-signed certificate when accessing the Web UI"
echo "2. Initial setup may take a few minutes to complete after container starts"
echo "3. For production use, update all passwords in docker-compose.openxpki.yml"
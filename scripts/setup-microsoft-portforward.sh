#!/bin/bash

# Microsoft Authenticator VS Code Port Forwarding Setup Script
# This script helps configure the demo environment for VS Code port forwarding access

set -e

echo "🚀 Microsoft Authenticator VS Code Port Forwarding Setup"
echo "========================================================"
echo

# Check if VS Code is installed
if ! command -v code &> /dev/null; then
    echo "❌ VS Code CLI not found. Please install VS Code first:"
    echo "   brew install --cask visual-studio-code"
    echo "   Or download from https://code.visualstudio.com/"
    exit 1
fi

echo "📝 Setting up environment file..."

# Create .env.microsoft from template
if [[ ! -f .env.microsoft.portforward.example ]]; then
    echo "❌ Template file .env.microsoft.portforward.example not found"
    exit 1
fi

cp .env.microsoft.portforward.example .env.microsoft

echo "✅ Created .env.microsoft from template"
echo

echo "🐳 Starting demo services..."
cd ..
docker compose -f docker/docker-compose.demo-microsoft-simple.yml up -d

echo "✅ Demo services started"
echo

echo "🌐 Now you need to set up port forwarding in VS Code:"
echo
echo "1. Open VS Code in this directory:"
echo "   code ."
echo
echo "2. Open Command Palette (Cmd+Shift+P or Ctrl+Shift+P)"
echo
echo "3. Type 'Ports: Focus on Ports View' and press Enter"
echo
echo "4. In the Ports panel, click 'Forward a Port'"
echo
echo "5. Add these ports with 'Public' visibility:"
echo "   - Port 8000 (Issuer API)"
echo "   - Port 8001 (Verifier API)"
echo
echo "6. Copy the generated URLs from the Ports panel (they'll look like:"
echo "   https://your-port-8000.preview.app.github.dev"
echo "   https://your-port-8001.preview.app.github.dev"
echo
echo "7. Update .env.microsoft with your actual forwarded URLs:"
echo "   Replace 'your-port-8000.preview.app.github.dev' with your actual issuer URL"
echo "   Replace 'your-port-8001.preview.app.github.dev' with your actual verifier URL"
echo
echo "8. Restart the services with the updated configuration:"
echo "   docker-compose -f docker/docker-compose.demo-microsoft-simple.yml --env-file .env.microsoft down"
echo "   docker-compose -f docker/docker-compose.demo-microsoft-simple.yml --env-file .env.microsoft up -d"
echo
echo "9. Test your services:"
echo "   curl https://your-actual-issuer-url/health"
echo "   curl https://your-actual-verifier-url/health"
echo
echo "10. Create a credential offer:"
echo "    curl -X POST https://your-actual-issuer-url/offer \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"credential_type\":\"MartyDigitalPassport\",\"subject_claims\":{\"given_name\":\"John\",\"family_name\":\"Doe\"}}'"
echo
echo "11. Open verifier demo on mobile:"
echo "    https://your-actual-verifier-url/demo"
echo
echo "🎉 Setup started! Complete the VS Code port forwarding steps above to finish."

echo
echo "💡 Pro tip: Keep VS Code open with the Ports panel visible to monitor your forwarded ports."
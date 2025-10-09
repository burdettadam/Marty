#!/bin/bash

# Microsoft Authenticator VS Code Tunnel Setup Script
# This script helps configure the demo environment for VS Code tunnel access

set -e

echo "🚀 Microsoft Authenticator VS Code Tunnel Setup"
echo "==============================================="
echo

# Check if VS Code CLI is available
if ! command -v code &> /dev/null; then
    echo "❌ VS Code CLI not found. Please install VS Code first:"
    echo "   brew install --cask visual-studio-code"
    echo "   Or download from https://code.visualstudio.com/"
    exit 1
fi

# Get tunnel name from user
echo "📝 Enter your tunnel name (e.g., 'marty-demo'):"
read -r TUNNEL_NAME

if [[ -z "$TUNNEL_NAME" ]]; then
    echo "❌ Tunnel name cannot be empty"
    exit 1
fi

echo
echo "🔧 Setting up environment file..."

# Create .env.microsoft from template
cp .env.microsoft.tunnel.example .env.microsoft

# Replace placeholder with actual tunnel name
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/YOUR_TUNNEL_NAME/$TUNNEL_NAME/g" .env.microsoft
else
    # Linux
    sed -i "s/YOUR_TUNNEL_NAME/$TUNNEL_NAME/g" .env.microsoft
fi

echo "✅ Created .env.microsoft with tunnel name: $TUNNEL_NAME"
echo

echo "🌐 Your tunnel URLs will be:"
echo "   Issuer:   https://8000-$TUNNEL_NAME.githubpreview.dev"
echo "   Verifier: https://8001-$TUNNEL_NAME.githubpreview.dev"
echo

echo "📋 Next steps:"
echo "1. Start your tunnel:"
echo "   code tunnel --name $TUNNEL_NAME --accept-server-license-terms"
echo
echo "2. In a new terminal, start the demo:"
echo "   docker-compose -f docker/docker-compose.demo-microsoft-simple.yml --env-file .env.microsoft up -d"
echo
echo "3. Test the services:"
echo "   curl https://8000-$TUNNEL_NAME.githubpreview.dev/health"
echo "   curl https://8001-$TUNNEL_NAME.githubpreview.dev/health"
echo
echo "4. Create a credential offer:"
echo "   curl -X POST https://8000-$TUNNEL_NAME.githubpreview.dev/offer -H 'Content-Type: application/json' -d '{\"credential_type\":\"MartyDigitalPassport\",\"subject_claims\":{\"given_name\":\"John\",\"family_name\":\"Doe\"}}'"
echo
echo "5. Open verifier demo on mobile:"
echo "   https://8001-$TUNNEL_NAME.githubpreview.dev/demo"
echo
echo "🎉 Setup complete! Happy testing with Microsoft Authenticator!"

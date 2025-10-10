#!/usr/bin/env python3
"""
Marty MMF Plugin Integration Demo

This script demonstrates how Marty works as a plugin for the MMF framework.
"""

import sys
import asyncio
from pathlib import Path

# Add the main Marty source to path
marty_src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(marty_src_path))

async def demo_plugin_discovery():
    """Demonstrate how MMF discovers the Marty plugin."""
    print("🔍 Plugin Discovery Demo")
    print("=" * 50)
    
    try:
        from src.mmf_plugin import MartyPlugin
        plugin = MartyPlugin()
        
        print(f"✅ Discovered plugin: {plugin.metadata.name}")
        print(f"   Version: {plugin.metadata.version}")
        print(f"   Description: {plugin.metadata.description}")
        
        metadata = plugin.get_metadata()
        print(f"   Services: {len(metadata['services'])} services")
        print(f"   Dependencies: {metadata['dependencies']}")
        print(f"   Tags: {plugin.metadata.tags}")
        
        return plugin
    except Exception as e:
        print(f"❌ Plugin discovery failed: {e}")
        return None

async def demo_plugin_lifecycle(plugin):
    """Demonstrate the plugin lifecycle."""
    print("\n🔄 Plugin Lifecycle Demo")
    print("=" * 50)
    
    if not plugin:
        print("❌ No plugin available for lifecycle demo")
        return
    
    try:
        # Mock plugin context (normally provided by MMF)
        class MockContext:
            def __init__(self):
                self.config_manager = None
        
        context = MockContext()
        
        # Initialize plugin
        print("🚀 Initializing plugin...")
        await plugin.initialize(context)
        print(f"   Plugin enabled: {plugin.config.enabled}")
        print(f"   Available services: {len(plugin.services)}")
        for service_name in plugin.services:
            print(f"   - {service_name}")
        
        # Start plugin services
        print("\n▶️  Starting plugin services...")
        await plugin.start()
        print("   All services started successfully")
        
        # Get health status
        print("\n❤️  Checking health status...")
        health = await plugin.health_check()
        print(f"   Overall status: {health['status']}")
        for service_name, service_health in health.get('services', {}).items():
            print(f"   - {service_name}: {service_health['status']}")
        
        # Stop services
        print("\n⏹️  Stopping plugin services...")
        await plugin.stop()
        print("   All services stopped successfully")
        
    except Exception as e:
        print(f"❌ Plugin lifecycle failed: {e}")

async def demo_configuration():
    """Demonstrate plugin configuration."""
    print("\n⚙️  Configuration Demo")
    print("=" * 50)
    
    try:
        from src.mmf_plugin import MartyTrustPKIConfig
        
        # Default configuration
        config = MartyTrustPKIConfig()
        print("📋 Default Configuration:")
        print(f"   Trust Anchor URL: {config.trust_anchor_url}")
        print(f"   PKD URL: {config.pkd_url}")
        print(f"   Document Signer URL: {config.document_signer_url}")
        print(f"   CSCA Service URL: {config.csca_service_url}")
        print(f"   Signing Algorithms: {config.signing_algorithms}")
        print(f"   Certificate Validation: {config.certificate_validation_enabled}")
        print(f"   ICAO Compliance: {config.icao_compliance_mode}")
        
        # Custom configuration
        print("\n📝 Custom Configuration Example:")
        custom_config = MartyTrustPKIConfig(
            trust_anchor_url="https://prod-trust.marty.com",
            pkd_url="https://prod-pkd.marty.com",
            signing_algorithms=["RSA-SHA256", "ECDSA-SHA256", "Ed25519"],
            require_mutual_tls=True
        )
        print(f"   Trust Anchor URL: {custom_config.trust_anchor_url}")
        print(f"   Mutual TLS Required: {custom_config.require_mutual_tls}")
        print(f"   Signing Algorithms: {custom_config.signing_algorithms}")
        
    except Exception as e:
        print(f"❌ Configuration demo failed: {e}")

async def demo_service_access():
    """Demonstrate service access through plugin."""
    print("\n🛠️  Service Access Demo")
    print("=" * 50)
    
    try:
        from src.mmf_plugin import MartyPlugin
        plugin = MartyPlugin()
        
        # Initialize with mock context
        class MockContext:
            config_manager = None
        
        await plugin.initialize(MockContext())
        
        print("🔧 Available Services:")
        services = plugin.get_services()
        for service_name in services:
            service = plugin.get_service(service_name)
            print(f"   - {service_name}: {type(service).__name__}")
            print(f"     Version: {service.version}")
        
        if services:
            # Demo service health check
            first_service = plugin.get_service(services[0])
            health = await first_service.get_health_status()
            print(f"\n💚 Sample Service Health ({services[0]}):")
            print(f"   Status: {health['status']}")
            print(f"   Service: {health['service']}")
            print(f"   Version: {health['version']}")
        
    except Exception as e:
        print(f"❌ Service access demo failed: {e}")

async def main():
    """Run the complete demo."""
    print("🎭 Marty MMF Plugin Integration Demo")
    print("=" * 50)
    print("This demo shows how Marty integrates with the MMF framework as a plugin.\n")
    
    # Plugin discovery
    plugin = await demo_plugin_discovery()
    
    # Plugin lifecycle
    await demo_plugin_lifecycle(plugin)
    
    # Configuration
    await demo_configuration()
    
    # Service access
    await demo_service_access()
    
    print("\n" + "=" * 50)
    print("🎉 Demo completed successfully!")
    print("\nKey Integration Points:")
    print("✅ Plugin discovery via entry points")
    print("✅ Configuration management")
    print("✅ Service lifecycle management")
    print("✅ Health monitoring")
    print("✅ MMF framework compatibility")
    print("\n📚 Next Steps:")
    print("1. Deploy MMF framework")
    print("2. Install Marty as plugin dependency")
    print("3. Configure plugin via config/plugins/marty.yaml")
    print("4. Start MMF with Marty plugin enabled")

if __name__ == "__main__":
    asyncio.run(main())
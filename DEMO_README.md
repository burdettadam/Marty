# Marty MMF Plugin Demo

A comprehensive demonstration of the Marty Trust PKI plugin integrated with the Marty Microservices Framework (MMF).

## 🚀 Quick Start

Test the Marty plugin integration:

```bash
# Run the plugin demo
python demo_mmf_integration.py

# Test plugin services individually  
python -c "from src.mmf_plugin.plugin import MartyPlugin; p=MartyPlugin(); print(f'Plugin: {p.get_metadata()}')"
```

## 📋 What's Demonstrated

### Plugin Integration

- **Plugin Discovery**: Demonstrates MMF plugin discovery and loading
- **Service Lifecycle**: Shows plugin service initialization, startup, and shutdown
- **Health Monitoring**: Plugin service health checks and status reporting
- **Configuration**: Plugin configuration management through MMF framework

### Available Services

The Marty plugin exposes four core trust and PKI services:

- **Trust Anchor Service**: Root certificate management and trust validation
- **PKD Service**: Public Key Directory synchronization and certificate discovery
- **Document Signer Service**: Digital signature creation for travel documents
- **CSCA Service**: Country Signing Certificate Authority management

### Dependency Analysis

The demo shows real-time dependency availability:

- ✅ **Trust Anchor**: Available with ModernTrustAnchor implementation
- ✅ **PKD Service**: Available with SimplePKDMirrorService implementation  
- ⚠️ **Document Signer**: Requires ServiceDependencies for full initialization
- ⚠️ **CSCA Service**: Requires ServiceDependencies for full initialization

## 🎯 Educational Value

This demo illustrates:

- **Plugin Architecture**: How to build plugins for the MMF framework
- **Service Integration**: Integrating domain-specific services with framework infrastructure
- **Dependency Management**: Handling service dependencies and graceful degradation
- **ICAO Standards**: Real implementations of ICAO Doc 9303 PKI components
## 🔧 Demo Output

When you run the demo, you'll see:

### Plugin Discovery
```
🔍 Plugin Discovery Demo
==================================================
✅ Discovered plugin: marty
   Version: 1.0.0
   Description: Marty Trust PKI services for ICAO compliance and document verification
   Services: 4 services
```

### Service Lifecycle  
```
🔄 Plugin Lifecycle Demo
==================================================
🚀 Initializing plugin...
✅ Started trust_anchor service
✅ Started pkd service  
✅ Started document_signer service
✅ Started csca service
```

### Health Monitoring
```
❤️  Checking health status...
   Overall status: healthy
   - trust_anchor: healthy
   - pkd: healthy
   - document_signer: healthy
   - csca: healthy
```

### Service Information
```
🔧 Available Services:
   - trust_anchor: TrustAnchorService (Version: 1.0.0)
   - pkd: PKDService (Version: 1.0.0)
   - document_signer: DocumentSignerService (Version: 1.0.0)
   - csca: CSCAService (Version: 1.0.0)
```

## 📚 Next Steps

1. **MMF Framework Deployment**: Deploy the MMF framework in your environment
2. **Plugin Installation**: Install Marty as a plugin dependency (`pip install marty-trust-pki-plugin`)
3. **Configuration**: Configure plugin settings via `config/plugins/marty.yaml`
4. **Integration**: Use the plugin services in your MMF applications

For production deployment, see the [MMF Framework documentation](./marty-microservices-framework/).

---

**🎓 Educational Focus**: This demo showcases how international digital identity standards can be implemented as modular, reusable plugins within modern framework architectures.

---

**Happy exploring the Marty MMF plugin! 🎉**

For questions or issues, see the MMF Framework documentation or create an issue in the repository.

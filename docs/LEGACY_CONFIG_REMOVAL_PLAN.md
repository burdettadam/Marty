# Legacy Configuration Removal Plan

## Files to Remove/Replace

### Legacy Configuration Managers (to be removed)
- `/src/marty_common/service_config_factory.py` - Legacy service config factory 
- `/src/marty_common/config_manager.py` - Legacy configuration manager
- `/src/marty_common/config/enhanced_config.py` - Enhanced config (if exists)

### Core Configuration (to be updated)
- `/src/marty_common/config.py` - Update to use MMF unified config or deprecate

### Services Using Legacy Config (to be updated)
- `/src/trust_anchor/app/services/certificate_revocation_service.py`
- `/src/trust_anchor/app/services/certificate_expiry_service.py` 
- `/src/trust_anchor/app/grpc_service.py`
- `/src/mdl_engine/src/main.py`
- `/src/mdl_engine/src/main_old.py`
- `/src/pkd_service/app/core/config_dry.py`
- `/src/services/document_signer/document_signer.py`
- `/src/apps/runtime.py`
- `/src/apps/credential_ledger.py`

## Migration Strategy

1. **Replace legacy config imports** with modern MMF config imports
2. **Update service initialization** to use `create_service_config()`
3. **Remove legacy config manager instances** and replace with modern config access
4. **Update environment variable patterns** to match modern config conventions
5. **Remove deprecated configuration files** after services are migrated

## Modern Configuration Patterns

### Instead of:
```python
from marty_common.service_config_factory import get_config_manager
config_manager = get_config_manager("trust-anchor")
port = config_manager.get_env_int("GRPC_PORT", 50051)
```

### Use:
```python
from framework.config_factory import create_service_config
config = create_service_config("config/services/trust_anchor.yaml")
port = config.service_discovery.ports.get("trust_anchor", 50051)
```

## Implementation Steps

1. Create modern config files for services that don't have them yet
2. Update service imports to use MMF config system
3. Replace config manager usage with modern config access patterns
4. Remove legacy configuration manager files
5. Update documentation to reflect modern patterns only
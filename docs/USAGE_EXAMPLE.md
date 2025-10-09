# Consolidated Logging Example

This example shows how to use the new consolidated logging utilities to replace manual logging setup across services.

## Before (Manual Logging Setup)

```python
import logging

class MyService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Service starting")

    def process_request(self, request_id: str):
        self.logger.info(f"Processing request {request_id}")
        # ... processing logic ...
        self.logger.info(f"Completed request {request_id}")
```

## After (Consolidated Logging)

```python
from marty_common.logging import ServiceLogger, PerformanceTimer

class MyService:
    def __init__(self):
        self.logger = ServiceLogger("my-service", __name__)
        self.logger.log_service_startup()

    def process_request(self, request_id: str):
        with PerformanceTimer(self.logger, "process_request"):
            self.logger.log_request_start(request_id, "process_request")
            # ... processing logic ...
            self.logger.log_request_end(request_id, "process_request", success=True)
```

## Using the Mixin Pattern

```python
from marty_common.services import BaseService
from marty_common.logging import LoggingMixin

class MyService(BaseService, LoggingMixin):
    def __init__(self):
        super().__init__()
        self.init_logging("my-service")
        self.logger.log_service_startup()
```

## Benefits

1. **Consistent Log Format**: All services use the same structured logging format
2. **Service Context**: Every log includes service name automatically
3. **Performance Tracking**: Built-in timing capabilities
4. **Standardized Events**: Common patterns for service lifecycle and request processing
5. **DRY Pattern**: No more repetitive logging setup code

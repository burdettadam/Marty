# Document Signer Service Refactoring

This directory contains the refactored Document Signer service, broken down into smaller, more manageable modules:

## File Structure

```
document_signer/
├── __init__.py              # Package initialization
├── document_signer.py       # Main DocumentSigner gRPC service class
├── certificate_manager.py   # Certificate management utilities
├── sd_jwt_manager.py       # SD-JWT credential management
├── storage_manager.py      # Storage operations
├── utils.py                # Utility functions and helpers
└── errors.py               # Error handling utilities (for future use)
```

## Modules Overview

### `document_signer.py`
The main service class that implements the gRPC DocumentSignerServicer. It coordinates between the other modules and handles the core business logic for document signing and SD-JWT credential issuance.

### `certificate_manager.py`
Handles certificate-related operations:
- Loading and creating document signer certificates
- Managing certificate chains for x5c headers
- Caching certificate data

### `sd_jwt_manager.py`
Manages SD-JWT credential operations:
- Creating credential offers
- Redeeming pre-authorized codes
- Issuing SD-JWT credentials
- Managing OIDC sessions

### `storage_manager.py`
Handles object storage operations:
- Storing SD-JWT tokens and disclosures
- Storing document signatures
- Managing storage keys and paths

### `utils.py`
Contains utility functions:
- Time calculations (`seconds_until`)
- Event payload building
- Common helper functions

### `errors.py`
Contains error handling utilities (created but not yet used):
- Standardized error creation functions
- Common error types for the service

## Benefits of Refactoring

1. **Separation of Concerns**: Each module has a specific responsibility
2. **Easier Testing**: Individual components can be tested in isolation
3. **Better Maintainability**: Smaller files are easier to understand and modify
4. **Reusability**: Components can be reused across different services
5. **Cleaner Code**: Reduced complexity in the main service class

## Usage

The refactored service maintains the same external API. You can import it as:

```python
from services.document_signer import DocumentSigner
```

## Notes

- The original `document_signer.py` has been backed up as `document_signer_original.py`
- Import fallbacks are included to handle development scenarios where protobuf imports might fail
- Type hints have been improved throughout the codebase
- Some linting issues remain and can be addressed in future iterations
# Marty Platform API Documentation

This directory contains automatically generated API documentation for all Marty Platform services.

## Generated Documentation

### 📖 View Documentation

- **[Complete Platform Documentation](index.html)** - Main documentation page with links to all services
- **[Combined API Documentation](static/marty_platform_docs.html)** - All services in one interactive document

### Individual Service Documentation

- **[PKD Service](static/pkd_service_docs.html)** - ICAO PKD API for Public Key Directory management
- **[Document Processing](static/document_processing_docs.html)** - Document Processing MRZ API for verification  
- **[UI Application](static/ui_app_docs.html)** - Marty Platform Web UI and operator interface

### OpenAPI Specifications

The `openapi/` directory contains machine-readable API specifications:

- `marty_platform_combined_openapi.json` - Combined specification for all services
- `pkd_service_openapi.json` - PKD Service specification
- `document_processing_openapi.json` - Document Processing specification
- `ui_app_openapi.json` - UI Application specification

## Live API Documentation

When services are running, you can access live interactive documentation:

- **PKD Service**: <http://localhost:8088/docs>
- **Document Processing**: <http://localhost:8080/docs>  
- **UI Application**: <http://localhost:8000/docs>

## Regenerating Documentation

To regenerate the API documentation:

```bash
# Using the script
./scripts/generate_docs.sh

# Using make
make docs

# Using Python directly
uv run python scripts/generate_simple_docs.py
```

## Serving Documentation Locally

To serve the documentation on a local web server:

```bash
# Using make (serves on http://localhost:8000)
make docs-serve

# Using Python directly
cd docs/api && python -m http.server 8000
```

## Files Structure

```
docs/api/
├── index.html                          # Main documentation page
├── openapi/                           # OpenAPI specifications
│   ├── marty_platform_combined_openapi.json
│   ├── pkd_service_openapi.json
│   ├── document_processing_openapi.json
│   └── ui_app_openapi.json
└── static/                            # Interactive HTML documentation
    ├── marty_platform_docs.html
    ├── pkd_service_docs.html
    ├── document_processing_docs.html
    └── ui_app_docs.html
```

---

*Generated automatically by the Marty Platform API documentation generator*

#!/usr/bin/env python3
"""
Simple API Documentation Generator for Marty Platform

Generates basic API documentation by creating individual spec files for each FastAPI service.
"""

import json
import logging
import sys
from pathlib import Path

# Add src to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OUTPUT_DIR = PROJECT_ROOT / "docs" / "api"
STATIC_DIR = OUTPUT_DIR / "static"

def setup_output_directories() -> None:
    """Create output directories for API documentation."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "openapi").mkdir(exist_ok=True)
    logger.info(f"Created output directories: {OUTPUT_DIR}")

def create_basic_openapi_spec(service_name: str, description: str, port: int) -> dict:
    """Create a basic OpenAPI specification for a service."""
    return {
        "openapi": "3.0.2",
        "info": {
            "title": f"{service_name.title()} API",
            "description": description,
            "version": "1.0.0",
            "contact": {
                "name": "Marty Platform Team",
                "url": "https://github.com/burdettadam/Marty",
            },
            "license": {"name": "Proprietary"},
        },
        "servers": [
            {"url": f"http://localhost:{port}", "description": "Development server"},
            {"url": "https://api.marty.platform", "description": "Production server"},
        ],
        "paths": {
            "/": {
                "get": {
                    "summary": "Root endpoint",
                    "description": f"Root endpoint for {service_name} service",
                    "responses": {
                        "200": {
                            "description": "Service information",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"},
                                            "version": {"type": "string"},
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "tags": [service_name]
                }
            },
            "/docs": {
                "get": {
                    "summary": "API Documentation",
                    "description": f"Interactive API documentation for {service_name}",
                    "responses": {
                        "200": {
                            "description": "HTML documentation page",
                            "content": {"text/html": {"schema": {"type": "string"}}}
                        }
                    },
                    "tags": [service_name]
                }
            },
            "/openapi.json": {
                "get": {
                    "summary": "OpenAPI Specification",
                    "description": f"OpenAPI 3.0 specification for {service_name}",
                    "responses": {
                        "200": {
                            "description": "OpenAPI specification",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "description": "OpenAPI 3.0 specification"
                                    }
                                }
                            }
                        }
                    },
                    "tags": [service_name]
                }
            }
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key for authentication"
                }
            }
        },
        "tags": [
            {
                "name": service_name,
                "description": description
            }
        ]
    }

def generate_service_docs():
    """Generate documentation for all known services."""
    services = {
        "pkd_service": {
            "description": "ICAO PKD API for Public Key Directory management",
            "port": 8088,
        },
        "document_processing": {
            "description": "Document Processing MRZ API for document verification",
            "port": 8080,
        },
        "ui_app": {
            "description": "Marty Platform Web UI and operator interface",
            "port": 8000,
        },
    }
    
    specs = {}
    openapi_dir = OUTPUT_DIR / "openapi"
    
    for service_name, config in services.items():
        logger.info(f"Generating documentation for {service_name}...")
        
        # Create basic OpenAPI spec
        spec = create_basic_openapi_spec(
            service_name, 
            config["description"], 
            config["port"]
        )
        specs[service_name] = spec
        
        # Save individual service specs
        json_path = openapi_dir / f"{service_name}_openapi.json"
        with json_path.open("w") as f:
            json.dump(spec, f, indent=2)
        logger.info(f"Saved OpenAPI JSON spec: {json_path}")
    
    return specs

def create_combined_spec(specs: dict) -> dict:
    """Create a combined OpenAPI specification for all services."""
    combined = {
        "openapi": "3.0.2",
        "info": {
            "title": "Marty Platform API",
            "description": "Comprehensive API documentation for the Marty enterprise document platform",
            "version": "1.0.0",
            "contact": {
                "name": "Marty Platform Team",
                "url": "https://github.com/burdettadam/Marty",
            },
            "license": {"name": "Proprietary"},
        },
        "servers": [
            {"url": "http://localhost", "description": "Development environment"},
            {"url": "https://api.marty.platform", "description": "Production environment"},
        ],
        "paths": {},
        "components": {"schemas": {}, "securitySchemes": {}},
        "tags": [],
    }
    
    for service_name, spec in specs.items():
        # Add service tag
        service_tag = {
            "name": service_name,
            "description": spec.get("info", {}).get("description", f"{service_name} service"),
        }
        combined["tags"].append(service_tag)
        
        # Merge paths with service prefix
        for path, path_spec in spec.get("paths", {}).items():
            prefixed_path = f"/{service_name}{path}"
            combined["paths"][prefixed_path] = path_spec
        
        # Merge components
        if "components" in spec:
            if "securitySchemes" in spec["components"]:
                combined["components"]["securitySchemes"].update(spec["components"]["securitySchemes"])
    
    return combined

def generate_redoc_html(spec_path: Path, output_path: Path, title: str) -> None:
    """Generate Redoc HTML documentation from OpenAPI spec."""
    html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body {{ margin: 0; padding: 0; }}
    </style>
</head>
<body>
    <redoc spec-url="../openapi/{spec_path.name}"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.0/bundles/redoc.standalone.js"></script>
</body>
</html>"""
    
    with output_path.open("w") as f:
        f.write(html_template)
    logger.info(f"Generated Redoc HTML: {output_path}")

def generate_index_page() -> None:
    """Generate an index page for all API documentation."""
    services = [
        ("pkd_service", "ICAO PKD API for Public Key Directory management"),
        ("document_processing", "Document Processing MRZ API for document verification"),
        ("ui_app", "Marty Platform Web UI and operator interface"),
    ]
    
    services_list = ""
    for service_name, description in services:
        services_list += f"""
        <div class="service">
            <h3>{service_name.replace('_', ' ').title()}</h3>
            <p>{description}</p>
            <p>
                <a href="static/{service_name}_docs.html">📖 Documentation</a> |
                <a href="openapi/{service_name}_openapi.json">📄 OpenAPI JSON</a>
            </p>
        </div>"""
    
    index_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Marty Platform API Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #2c3e50; }}
        .service {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .service h3 {{ color: #3498db; margin-top: 0; }}
        a {{ color: #3498db; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .combined {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Marty Platform API Documentation</h1>
        <p>Enterprise-grade microservices platform for secure digital identity document management.</p>
        
        <div class="service combined">
            <h3>🌟 Combined Platform API</h3>
            <p>Complete API documentation for all Marty services in one place.</p>
            <p>
                <a href="static/marty_platform_docs.html">📖 View Combined Documentation</a> |
                <a href="openapi/marty_platform_combined_openapi.json">📄 OpenAPI JSON</a>
            </p>
        </div>
        
        <h2>Individual Services</h2>
        {services_list}
        
        <hr>
        <p><small>Generated automatically by the Marty Platform API documentation generator.</small></p>
        <p><small>
            For live API documentation of running services, visit:
            <br>• PKD Service: <a href="http://localhost:8088/docs">http://localhost:8088/docs</a>
            <br>• Document Processing: <a href="http://localhost:8080/docs">http://localhost:8080/docs</a>
            <br>• UI App: <a href="http://localhost:8000/docs">http://localhost:8000/docs</a>
        </small></p>
    </div>
</body>
</html>"""
    
    index_path = OUTPUT_DIR / "index.html"
    with index_path.open("w") as f:
        f.write(index_html)
    logger.info(f"Generated index page: {index_path}")

def main() -> None:
    """Main function to generate all API documentation."""
    try:
        logger.info("🚀 Starting API documentation generation for Marty Platform")
        
        # Setup output directories
        setup_output_directories()
        
        # Generate service documentation
        specs = generate_service_docs()
        
        # Create combined specification
        combined_spec = create_combined_spec(specs)
        combined_json_path = OUTPUT_DIR / "openapi" / "marty_platform_combined_openapi.json"
        with combined_json_path.open("w") as f:
            json.dump(combined_spec, f, indent=2)
        logger.info(f"Saved combined OpenAPI spec: {combined_json_path}")
        
        # Generate HTML documentation
        openapi_dir = OUTPUT_DIR / "openapi"
        
        # Individual service docs
        for service_name in specs.keys():
            json_spec_path = openapi_dir / f"{service_name}_openapi.json"
            html_path = STATIC_DIR / f"{service_name}_docs.html"
            generate_redoc_html(json_spec_path, html_path, f"{service_name.title()} API")
        
        # Combined docs
        combined_html_path = STATIC_DIR / "marty_platform_docs.html"
        generate_redoc_html(combined_json_path, combined_html_path, "Marty Platform API")
        
        # Generate index page
        generate_index_page()
        
        logger.info("✅ API documentation generation completed successfully!")
        logger.info(f"📖 Documentation available at: {OUTPUT_DIR / 'index.html'}")
        logger.info("💡 Note: For complete live API docs, start the services and visit their /docs endpoints")
        
    except Exception as e:
        logger.exception(f"❌ API documentation generation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
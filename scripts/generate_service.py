#!/usr/bin/env python3
"""
Marty Service Generator - DRY Service Template Engine

This script generates new Marty services using DRY templates, automatically
incorporating all established patterns:
- Base configuration classes
- gRPC Service Factory patterns
- Docker base image usage
- DRY testing infrastructure
- Consistent project structure

Usage:
    python generate_service.py [service_type] [service_name] [options]

Examples:
    python generate_service.py grpc document-validator
    python generate_service.py fastapi user-management --http-port 8080
    python generate_service.py hybrid payment-processor --grpc-port 50052 --http-port 8082
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("Error: Jinja2 is required for template generation.")
    print("Install it with: pip install jinja2")
    sys.exit(1)


class ServiceGenerator:
    """Generator for Marty services using DRY templates."""
    
    def __init__(self, templates_dir: Path, output_dir: Path) -> None:
        """
        Initialize the service generator.
        
        Args:
            templates_dir: Path to templates directory
            output_dir: Path to output directory (src/)
        """
        self.templates_dir = templates_dir
        self.output_dir = output_dir
        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            trim_blocks=True,
            lstrip_blocks=True,
        )
    
    def generate_service(
        self,
        service_type: str,
        service_name: str,
        **options: Any
    ) -> None:
        """
        Generate a new service from templates.
        
        Args:
            service_type: Type of service (grpc, fastapi, hybrid, minimal)
            service_name: Name of the service (e.g., "document-validator")
            **options: Additional template variables
        """
        # Validate service type
        valid_types = ["grpc", "fastapi", "hybrid", "minimal"]
        if service_type not in valid_types:
            raise ValueError(f"Service type must be one of: {valid_types}")
        
        # Prepare template variables
        template_vars = self._prepare_template_vars(service_name, **options)
        
        # Determine template directory
        if service_type == "grpc":
            template_subdir = "service/grpc_service"
        elif service_type == "fastapi":
            template_subdir = "service/fastapi_service"
        elif service_type == "hybrid":
            template_subdir = "service/hybrid_service"
        else:  # minimal
            template_subdir = "service/minimal_service"
        
        # Generate service files
        self._generate_from_template_dir(template_subdir, template_vars)
        
        print(f"✅ Generated {service_type} service: {service_name}")
        print(f"📁 Location: {self.output_dir / template_vars['service_package']}")
        print(f"🚀 To get started:")
        print(f"   1. Review and customize the generated configuration")
        print(f"   2. Implement your business logic in the service class")
        print(f"   3. Add your API endpoints or gRPC methods")
        print(f"   4. Run tests: pytest src/{template_vars['service_package']}/tests/")
        print(f"   5. Build Docker image: docker build -f src/{template_vars['service_package']}/Dockerfile .")
    
    def _prepare_template_vars(self, service_name: str, **options: Any) -> dict[str, Any]:
        """
        Prepare template variables from service name and options.
        
        Args:
            service_name: Service name (e.g., "document-validator")
            **options: Additional options
            
        Returns:
            Dictionary of template variables
        """
        # Convert service name to different formats
        service_package = service_name.replace("-", "_")
        service_class = self._to_class_name(service_name)
        
        # Default template variables
        template_vars = {
            "service_name": service_name,
            "service_package": service_package,
            "service_class": service_class,
            "service_description": options.get(
                "description",
                f"{service_class} service for {service_name} functionality"
            ),
            "author": options.get("author", "Marty Development Team"),
            "grpc_port": options.get("grpc_port", 50051),
            "http_port": options.get("http_port", 8080),
        }
        
        # Add any additional options
        template_vars.update(options)
        
        return template_vars
    
    def _to_class_name(self, service_name: str) -> str:
        """
        Convert service name to PascalCase class name.
        
        Args:
            service_name: Service name (e.g., "document-validator")
            
        Returns:
            PascalCase class name (e.g., "DocumentValidator")
        """
        # Split on hyphens and underscores, capitalize each part
        parts = re.split(r"[-_]", service_name)
        return "".join(part.capitalize() for part in parts if part)
    
    def _generate_from_template_dir(
        self,
        template_subdir: str,
        template_vars: dict[str, Any]
    ) -> None:
        """
        Generate files from a template directory.
        
        Args:
            template_subdir: Subdirectory containing templates
            template_vars: Variables for template rendering
        """
        template_dir = self.templates_dir / template_subdir
        if not template_dir.exists():
            raise ValueError(f"Template directory not found: {template_dir}")
        
        # Create output directory structure
        service_dir = self.output_dir / template_vars["service_package"]
        service_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (service_dir / "app").mkdir(exist_ok=True)
        (service_dir / "app" / "api").mkdir(exist_ok=True)
        (service_dir / "app" / "core").mkdir(exist_ok=True)
        (service_dir / "app" / "services").mkdir(exist_ok=True)
        (service_dir / "tests").mkdir(exist_ok=True)
        
        # Generate files from templates
        for template_file in template_dir.glob("*.j2"):
            self._generate_file(template_file, template_subdir, service_dir, template_vars)
    
    def _generate_file(
        self,
        template_file: Path,
        template_subdir: str,
        service_dir: Path,
        template_vars: dict[str, Any]
    ) -> None:
        """
        Generate a single file from template.
        
        Args:
            template_file: Path to template file
            template_subdir: Template subdirectory
            service_dir: Output service directory
            template_vars: Template variables
        """
        # Determine output file path
        relative_path = template_file.relative_to(self.templates_dir / template_subdir)
        output_file = service_dir / relative_path.with_suffix("")
        
        # Map template files to output locations
        file_mapping = {
            "main.py": service_dir / "main.py",
            "config.py": service_dir / "app" / "core" / "config.py",
            "service.py": service_dir / "app" / "services" / f"{template_vars['service_package']}_service.py",
            "grpc_service.py": service_dir / "app" / "services" / "grpc_service.py",
            "routes.py": service_dir / "app" / "api" / "routes.py",
            "middleware.py": service_dir / "app" / "core" / "middleware.py",
            "error_handlers.py": service_dir / "app" / "core" / "error_handlers.py",
            "test_service.py": service_dir / "tests" / f"test_{template_vars['service_package']}_service.py",
            "Dockerfile": service_dir / "Dockerfile",
            "service.proto": service_dir / f"{template_vars['service_package']}.proto",
        }
        
        # Get actual output path
        output_path = file_mapping.get(relative_path.name, output_file)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Render template
        template_path = f"{template_subdir}/{relative_path.name}"
        template = self.env.get_template(template_path)
        rendered_content = template.render(**template_vars)
        
        # Write output file
        output_path.write_text(rendered_content, encoding="utf-8")
        print(f"  📝 Generated: {output_path.relative_to(self.output_dir.parent)}")


def main() -> None:
    """Main entry point for service generation."""
    parser = argparse.ArgumentParser(
        description="Generate new Marty services using DRY templates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s grpc document-validator
  %(prog)s fastapi user-management --http-port 8080
  %(prog)s hybrid payment-processor --grpc-port 50052 --http-port 8082
  %(prog)s grpc certificate-checker --description "Certificate validation service"

Service Types:
  grpc      - gRPC-only service with protocol buffers
  fastapi   - HTTP REST API service with FastAPI
  hybrid    - Combined gRPC and FastAPI service
  minimal   - Minimal service with base configuration only
        """
    )
    
    parser.add_argument(
        "service_type",
        choices=["grpc", "fastapi", "hybrid", "minimal"],
        help="Type of service to generate"
    )
    
    parser.add_argument(
        "service_name",
        help="Name of the service (e.g., document-validator)"
    )
    
    parser.add_argument(
        "--description",
        help="Service description"
    )
    
    parser.add_argument(
        "--author",
        default="Marty Development Team",
        help="Author name (default: Marty Development Team)"
    )
    
    parser.add_argument(
        "--grpc-port",
        type=int,
        default=50051,
        help="gRPC port (default: 50051)"
    )
    
    parser.add_argument(
        "--http-port",
        type=int,
        default=8080,
        help="HTTP port for FastAPI services (default: 8080)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory (default: ./src)"
    )
    
    args = parser.parse_args()
    
    # Determine directories
    script_dir = Path(__file__).parent
    templates_dir = script_dir / "templates"
    output_dir = args.output_dir or (script_dir / "src")
    
    # Validate inputs
    if not templates_dir.exists():
        print(f"Error: Templates directory not found: {templates_dir}")
        sys.exit(1)
    
    # Validate service name
    if not re.match(r"^[a-z][a-z0-9-]*[a-z0-9]$", args.service_name):
        print("Error: Service name must be lowercase with hyphens (e.g., document-validator)")
        sys.exit(1)
    
    # Check if service already exists
    service_package = args.service_name.replace("-", "_")
    if (output_dir / service_package).exists():
        response = input(f"Service '{service_package}' already exists. Overwrite? (y/N): ")
        if response.lower() != "y":
            print("Generation cancelled.")
            sys.exit(0)
    
    try:
        # Create generator and generate service
        generator = ServiceGenerator(templates_dir, output_dir)
        generator.generate_service(
            service_type=args.service_type,
            service_name=args.service_name,
            description=args.description,
            author=args.author,
            grpc_port=args.grpc_port,
            http_port=args.http_port,
        )
        
    except Exception as e:
        print(f"Error generating service: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
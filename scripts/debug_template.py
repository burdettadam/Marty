#!/usr/bin/env python3
"""
Debug script to find specific syntax errors in templates.
"""

import ast
import tempfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def debug_template_generation(template_name: str):
    """Debug template generation to find specific errors."""
    project_root = Path(__file__).parent.parent
    templates_dir = project_root / "templates" / "service"
    template_dir = templates_dir / template_name

    # Template variables for testing
    template_vars = {
        "service_name": "test-service",
        "service_package": "test_service",
        "service_class": "Test",
        "service_description": "Test service for template validation",
        "service_version": "1.0.0",
        "grpc_port": 50051,
        "http_port": 8000,
        "author_name": "Test Author",
        "author_email": "test@example.com",
    }

    # Create Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Generate all template files
        template_files = list(template_dir.glob("**/*.j2"))

        for template_file in template_files:
            try:
                # Get relative path and remove .j2 extension
                relative_path = template_file.relative_to(template_dir)
                output_path = temp_path / str(relative_path)[:-3]  # Remove .j2

                # Ensure output directory exists
                output_path.parent.mkdir(parents=True, exist_ok=True)

                # Render template
                template = env.get_template(str(relative_path))
                rendered_content = template.render(**template_vars)

                # Write rendered content
                output_path.write_text(rendered_content, encoding="utf-8")

                # Check Python syntax if it's a .py file
                if output_path.suffix == ".py":
                    try:
                        ast.parse(rendered_content, filename=str(output_path))
                        print(f"✅ {relative_path}: Valid Python syntax")
                    except SyntaxError as e:
                        print(f"❌ {relative_path}: Syntax error at line {e.lineno}")
                        print(f"    Error: {e.msg}")
                        print(f"    Text: {e.text}")

                        # Show context around the error
                        lines = rendered_content.splitlines()
                        start = max(0, e.lineno - 3)
                        end = min(len(lines), e.lineno + 2)

                        print("    Context:")
                        for i in range(start, end):
                            marker = ">>> " if i + 1 == e.lineno else "    "
                            print(f"    {marker}{i+1:3}: {lines[i]}")
                        print()

            except Exception as e:
                print(f"❌ {relative_path}: Template rendering error: {e}")


if __name__ == "__main__":
    debug_template_generation("grpc_service")

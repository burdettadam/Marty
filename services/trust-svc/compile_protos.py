#!/usr/bin/env python3
"""
Compile Protocol Buffer definitions and generate Python gRPC code.

This script compiles the trust_service.proto file and generates the necessary
Python files for gRPC client and server implementations.
"""

import subprocess
import sys
from pathlib import Path


def compile_protos():
    """Compile Protocol Buffer definitions."""

    # Get the service root directory
    service_root = Path(__file__).parent
    proto_dir = service_root / "proto"
    output_dir = service_root / "src" / "grpc_generated"

    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create __init__.py file
    (output_dir / "__init__.py").touch()

    # Proto files to compile
    proto_files = ["trust_service.proto"]

    for proto_file in proto_files:
        proto_path = proto_dir / proto_file

        if not proto_path.exists():
            print(f"Error: Proto file not found: {proto_path}")
            sys.exit(1)

        print(f"Compiling {proto_file}...")

        # Compile with protoc
        cmd = [
            "python",
            "-m",
            "grpc_tools.protoc",
            f"--proto_path={proto_dir}",
            f"--python_out={output_dir}",
            f"--grpc_python_out={output_dir}",
            f"--pyi_out={output_dir}",  # Generate type stubs
            str(proto_path),
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"Successfully compiled {proto_file}")

        except subprocess.CalledProcessError as e:
            print(f"Error compiling {proto_file}:")
            print(f"Command: {' '.join(cmd)}")
            print(f"Return code: {e.returncode}")
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")
            sys.exit(1)

        except FileNotFoundError:
            print("Error: protoc or grpc_tools not found.")
            print("Install with: pip install grpcio-tools")
            sys.exit(1)

    # Fix imports in generated files
    fix_imports(output_dir)

    print("Proto compilation completed successfully!")


def fix_imports(output_dir):
    """Fix relative imports in generated gRPC files."""

    grpc_files = list(output_dir.glob("*_pb2_grpc.py"))

    for grpc_file in grpc_files:
        print(f"Fixing imports in {grpc_file.name}...")

        # Read the file
        with open(grpc_file, encoding="utf-8") as f:
            content = f.read()

        # Fix imports (replace absolute imports with relative)
        content = content.replace(
            "import trust_service_pb2 as trust__service__pb2",
            "from . import trust_service_pb2 as trust__service__pb2",
        )

        # Write back
        with open(grpc_file, "w", encoding="utf-8") as f:
            f.write(content)


if __name__ == "__main__":
    compile_protos()

#!/usr/bin/env python3
"""
Validate Service Isolation Patterns

This script validates that services maintain proper isolation:
- No cross-service imports or dependencies
- Proper API boundaries
- Service-specific configurations
- No shared mutable state
"""

import re
import sys
from pathlib import Path
from typing import List


def check_cross_service_imports() -> list[str]:
    """Check for imports that violate service boundaries."""
    issues = []

    # Map service directories to their allowed imports
    service_dirs = {}

    # Scan for service directories
    for service_path in Path("services").glob("*/"):
        if service_path.is_dir():
            service_dirs[service_path.name] = service_path

    # Check each service for cross-service imports
    for service_name, service_path in service_dirs.items():
        for py_file in service_path.glob("**/*.py"):
            if not py_file.exists():
                continue

            content = py_file.read_text(encoding="utf-8")

            # Look for imports from other services
            for other_service in service_dirs:
                if other_service != service_name:
                    pattern = rf"from\s+services\.{other_service}\s+import|import\s+services\.{other_service}"
                    if re.search(pattern, content):
                        issues.append(f"{py_file}: Cross-service import detected: {other_service}")

    return issues


def check_api_boundaries() -> list[str]:
    """Check that services expose proper API boundaries."""
    issues = []

    # Look for services without proper API definitions
    for service_path in Path("services").glob("*/"):
        if not service_path.is_dir():
            continue

        # Check for API definition files
        api_files = list(service_path.glob("**/api*.py"))
        api_files.extend(list(service_path.glob("**/routes*.py")))
        api_files.extend(list(service_path.glob("**/handlers*.py")))

        if not api_files:
            issues.append(f"{service_path}: Service missing API boundary definition")

        # Check for direct database access in API layer
        for api_file in api_files:
            if not api_file.exists():
                continue

            content = api_file.read_text(encoding="utf-8")

            # Look for direct database imports in API layer
            db_patterns = [
                r"from.*database.*import",
                r"import.*database",
                r"\.execute\s*\(",
                r"\.query\s*\(",
            ]

            for pattern in db_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # Allow if going through repository pattern
                    if "repository" not in content.lower():
                        issues.append(f"{api_file}: Direct database access in API layer")
                        break

    return issues


def check_shared_state() -> list[str]:
    """Check for shared mutable state between services."""
    issues = []

    # Look for global variables and singletons that might be shared
    for service_path in Path("services").glob("*/"):
        if not service_path.is_dir():
            continue

        for py_file in service_path.glob("**/*.py"):
            if not py_file.exists():
                continue

            content = py_file.read_text(encoding="utf-8")

            # Look for global mutable state
            global_patterns = [
                r"^[A-Z_]+\s*=\s*\[\]",  # Global lists
                r"^[A-Z_]+\s*=\s*\{\}",  # Global dicts
                r"^[A-Z_]+\s*=\s*set\(\)",  # Global sets
            ]

            for pattern in global_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    issues.append(f"{py_file}: Global mutable state detected")

    return issues


def check_configuration_isolation() -> list[str]:
    """Check that services have isolated configurations."""
    issues = []

    # Check that each service has its own config
    for service_path in Path("services").glob("*/"):
        if not service_path.is_dir():
            continue

        # Look for service-specific config files
        config_files = list(service_path.glob("**/config*.py"))
        config_files.extend(list(service_path.glob("**/settings*.py")))
        config_files.extend(list(service_path.glob("**/*.yaml")))
        config_files.extend(list(service_path.glob("**/*.yml")))

        if not config_files:
            # Check if using global config (which is acceptable if done properly)
            has_config_import = False
            for py_file in service_path.glob("**/*.py"):
                if not py_file.exists():
                    continue

                content = py_file.read_text(encoding="utf-8")
                if "config" in content.lower() or "settings" in content.lower():
                    has_config_import = True
                    break

            if not has_config_import:
                issues.append(f"{service_path}: Service missing configuration")

    return issues

    return issues


def validate_service_isolation() -> bool:
    """Run all service isolation validations."""
    print("🔍 Validating Service Isolation Patterns...")

    all_issues = []

    # Run all checks
    all_issues.extend(check_cross_service_imports())
    all_issues.extend(check_api_boundaries())
    all_issues.extend(check_shared_state())
    all_issues.extend(check_configuration_isolation())

    if all_issues:
        print("❌ Service isolation validation failed:")
        for issue in all_issues:
            print(f"  - {issue}")
        return False
    else:
        print("✅ Service isolation validation passed")
        return True


if __name__ == "__main__":
    success = validate_service_isolation()
    sys.exit(0 if success else 1)

#!/usr/bin/env python3
"""
Validate CLI and Framework Integration

This script validates CLI functionality and framework integration:
- CLI commands are properly registered
- Framework generators work correctly
- Plugin system integration
- Template generation functionality
"""

import importlib.util
import sys
from pathlib import Path
from typing import List

# Ensure framework root (containing marty_cli and src) is on sys.path for import resolution
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Workaround: Some third-party libs (older versions) attempt 'from typing import list, tuple' under Python 3.13.
# Patch import machinery to tolerate this by creating aliases if missing.
import typing  # pragma: no cover
if not hasattr(typing, "list"):
    setattr(typing, "list", list)  # type: ignore[attr-defined]
if not hasattr(typing, "tuple"):
    setattr(typing, "tuple", tuple)  # type: ignore[attr-defined]


def check_cli_commands() -> list[str]:
    """Check that CLI commands are properly defined."""
    issues = []

    cli_files = []
    cli_files.extend(list(Path("marty_cli").glob("**/*.py")))
    cli_files.extend(list(Path("src/framework/generators").glob("**/*.py")))

    for cli_file in cli_files:
        if not cli_file.exists():
            continue

        try:
            content = cli_file.read_text(encoding="utf-8")

            # Check for Click or argparse command definitions
            if "@click.command" in content or "@click.group" in content:
                # Check for proper help text
                if "--help" not in content and "help=" not in content:
                    issues.append(f"{cli_file}: CLI command missing help text")

            # Check for main entry points
            if "def main(" in content or "if __name__ == '__main__':" in content:
                # Check for proper error handling
                if "try:" not in content and "except" not in content:
                    issues.append(f"{cli_file}: Main function missing error handling")

        except (OSError, UnicodeDecodeError) as e:
            issues.append(f"{cli_file}: Error reading CLI file: {e}")

    return issues


def check_generator_functionality() -> list[str]:
    """Check that code generators work properly."""
    issues = []

    generator_files = list(Path("src/framework/generators").glob("**/*.py"))

    for gen_file in generator_files:
        if not gen_file.exists():
            continue

        try:
            content = gen_file.read_text(encoding="utf-8")

            # Check for template loading
            if "jinja2" in content.lower() or "template" in content.lower():
                # Check for proper template error handling
                if "TemplateNotFound" not in content and "template" in content.lower():
                    issues.append(f"{gen_file}: Generator missing template error handling")

            # Check for file generation functions
            if "generate" in content and "def " in content:
                # Check for proper path handling
                if "Path(" not in content and "os.path" not in content:
                    issues.append(f"{gen_file}: Generator should use proper path handling")

        except (OSError, UnicodeDecodeError) as e:
            issues.append(f"{gen_file}: Error reading generator file: {e}")

    return issues


def check_framework_imports() -> list[str]:
    """Check that framework components can be imported."""
    issues = []

    # Check key framework modules
    framework_modules = [
        "marty_cli",
        "src.framework.generators",
        "src.framework.database",
    ]

    for module_path in framework_modules:
        try:
            # Convert path to module name
            module_name = module_path.replace("/", ".").replace("\\", ".")

            # Try to find and load the module
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                # Try alternative path
                alt_path = Path(module_path.replace(".", "/"))
                if alt_path.exists():
                    init_file = alt_path / "__init__.py"
                    if not init_file.exists():
                        issues.append(f"{module_path}: Missing __init__.py file")
                else:
                    issues.append(f"{module_path}: Module not found")

        except ImportError as e:
            issues.append(f"{module_path}: Import error: {e}")
        # If importlib can't find a spec we already handled via spec None branch

    return issues


def check_template_integration() -> list[str]:
    """Check that template system integrates properly with CLI."""
    issues = []

    # Check for template directory structure
    template_dirs = list(Path("templates").glob("*-service"))

    if not template_dirs:
        issues.append("templates/: No service templates found")
        return issues

    # Check that CLI can access templates
    cli_template_refs = []
    for cli_file in Path("marty_cli").glob("**/*.py"):
        if not cli_file.exists():
            continue

        try:
            content = cli_file.read_text(encoding="utf-8")

            # Look for template references
            if "templates/" in content:
                cli_template_refs.append(cli_file)

        except (OSError, UnicodeDecodeError):
            continue

    if not cli_template_refs:
        issues.append("marty_cli/: CLI doesn't reference template system")

    return issues


def check_plugin_system() -> list[str]:
    """Check plugin system integration."""
    issues = []

    # Look for plugin directories
    plugin_dirs = []
    plugin_dirs.extend(list(Path("src").glob("**/plugins")))
    plugin_dirs.extend(list(Path("marty_chassis").glob("**/plugins")))

    for plugin_dir in plugin_dirs:
        if not plugin_dir.is_dir():
            continue

        # Check for plugin interface
        plugin_files = list(plugin_dir.glob("**/*.py"))
        has_interface = False

        for plugin_file in plugin_files:
            if not plugin_file.exists():
                continue

            try:
                content = plugin_file.read_text(encoding="utf-8")

                if "class" in content and "Plugin" in content:
                    has_interface = True

                    # Check for required plugin methods
                    required_methods = ["initialize", "activate"]
                    for method in required_methods:
                        if f"def {method}" not in content:
                            issues.append(f"{plugin_file}: Plugin missing {method} method")

            except (OSError, UnicodeDecodeError):
                continue

        if plugin_files and not has_interface:
            issues.append(f"{plugin_dir}: Plugin directory missing plugin interface")

    return issues


def validate_cli_functionality() -> bool:
    """Run all CLI and framework integration checks."""
    print("🔍 Validating CLI and Framework Integration...")

    all_issues = []

    # Run all checks
    all_issues.extend(check_cli_commands())
    all_issues.extend(check_generator_functionality())
    all_issues.extend(check_framework_imports())
    all_issues.extend(check_template_integration())
    all_issues.extend(check_plugin_system())

    if all_issues:
        print("❌ CLI and framework integration validation failed:")
        for issue in all_issues:
            print(f"  - {issue}")
        return False
    else:
        print("✅ CLI and framework integration validation passed")
        return True


if __name__ == "__main__":
    success = validate_cli_functionality()
    sys.exit(0 if success else 1)

#!/usr/bin/env python3
"""
Validate Database Abstraction Layer Implementation

This script validates that the database layer follows Marty Framework patterns:
- DatabaseManager singleton implementation
- Proper service isolation in database connections
- Transaction management patterns
- Repository pattern implementation
"""

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


def check_database_manager_singleton() -> list[str]:
    """Check DatabaseManager implements proper singleton pattern."""
    issues = []

    # Check Go implementation
    go_db_file = Path("templates/go-service/internal/database/database.go")
    if go_db_file.exists():
        content = go_db_file.read_text()

        # Check for sync.Once pattern
        if "sync.Once" not in content:
            issues.append(f"{go_db_file}: Missing sync.Once for thread-safe singleton")

        # Check for GetInstance method
        if "GetInstance" not in content:
            issues.append(f"{go_db_file}: Missing GetInstance method")

        # Check for proper error handling
        if "if err != nil" not in content:
            issues.append(f"{go_db_file}: Missing proper error handling")

    # Check Python implementation
    py_db_files = list(Path("src/framework/database").glob("**/*.py"))
    py_db_files.extend(list(Path("marty_chassis").glob("**/database*.py")))

    for db_file in py_db_files:
        if not db_file.exists():
            continue

        content = db_file.read_text()

        # Check for singleton pattern in Python
        if "DatabaseManager" in content:
            if "_instance" not in content and "__new__" not in content:
                issues.append(f"{db_file}: DatabaseManager should implement singleton pattern")

    return issues


def check_service_isolation() -> list[str]:
    """Check that database connections maintain service isolation."""
    issues = []

    # Look for hardcoded database names or cross-service access
    db_files = []
    db_files.extend(list(Path("src").glob("**/database*.py")))
    db_files.extend(list(Path("services").glob("**/database*.py")))
    db_files.extend(list(Path("templates").glob("**/database*")))

    for db_file in db_files:
        if not db_file.exists() or db_file.suffix not in [".py", ".go"]:
            continue

        content = db_file.read_text()

        # Check for hardcoded database names
        hardcoded_patterns = [
            r'database.*=.*"[^"]*"',  # database = "hardcoded_name"
            r'db_name.*=.*"[^"]*"',  # db_name = "hardcoded_name"
            r'Database.*=.*"[^"]*"',  # Database = "hardcoded_name"
        ]

        for pattern in hardcoded_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Filter out template variables and config references
                for match in matches:
                    if (
                        "{{" not in match
                        and "config" not in match.lower()
                        and "env" not in match.lower()
                    ):
                        issues.append(f"{db_file}: Possible hardcoded database name: {match}")

    return issues


def check_transaction_patterns() -> list[str]:
    """Check transaction management patterns."""
    issues = []

    # Look for proper transaction handling
    transaction_files = []
    transaction_files.extend(list(Path("src/framework/database").glob("**/*.py")))
    transaction_files.extend(list(Path("templates").glob("**/database*.py")))

    for trans_file in transaction_files:
        if not trans_file.exists():
            continue

        content = trans_file.read_text()

        # Check for transaction decorator or context manager
        if "transaction" in content.lower():
            if "@transactional" not in content and "with" not in content:
                # Look for manual transaction handling
                if "begin()" in content and (
                    "commit()" not in content or "rollback()" not in content
                ):
                    issues.append(
                        f"{trans_file}: Incomplete transaction handling - missing commit/rollback"
                    )

    return issues


def check_repository_patterns() -> list[str]:
    """Check repository pattern implementation."""
    issues = []

    # Look for repository files
    repo_files = []
    repo_files.extend(list(Path("src").glob("**/repositories/**/*.py")))
    repo_files.extend(list(Path("services").glob("**/repositories/**/*.py")))
    repo_files.extend(list(Path("templates").glob("**/repositories/**/*")))

    for repo_file in repo_files:
        if not repo_file.exists() or repo_file.suffix not in [".py", ".go"]:
            continue

        content = repo_file.read_text()

        # Check for proper repository interface
        if "Repository" in content:
            # Check for CRUD operations
            required_methods = ["create", "read", "update", "delete"]
            missing_methods = []

            for method in required_methods:
                if method not in content.lower():
                    missing_methods.append(method)

            if missing_methods:
                issues.append(
                    f"{repo_file}: Repository missing methods: {', '.join(missing_methods)}"
                )

    return issues


def validate_database_layer() -> bool:
    """Run all database layer validations."""
    print("🔍 Validating Database Abstraction Layer...")

    all_issues = []

    # Run all checks
    all_issues.extend(check_database_manager_singleton())
    all_issues.extend(check_service_isolation())
    all_issues.extend(check_transaction_patterns())
    all_issues.extend(check_repository_patterns())

    if all_issues:
        print("❌ Database layer validation failed:")
        for issue in all_issues:
            print(f"  - {issue}")
        return False
    else:
        print("✅ Database abstraction layer validation passed")
        return True


if __name__ == "__main__":
    success = validate_database_layer()
    sys.exit(0 if success else 1)

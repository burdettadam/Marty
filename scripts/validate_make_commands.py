#!/usr/bin/env python3
"""
Validation script for testing Make commands for OpenID4VP integration tests.
This script validates that all the new Make targets work correctly.
"""
import subprocess
import sys
from pathlib import Path


def run_command(cmd: str, description: str, expect_failure: bool = False) -> bool:
    """Run a command and return success status."""
    print(f"\n🔍 {description}")
    print(f"Command: {cmd}")
    
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        if expect_failure:
            if result.returncode != 0:
                print("✅ Expected failure - command failed as expected")
                return True
            else:
                print("❌ Expected failure but command succeeded")
                return False
        else:
            if result.returncode == 0:
                print("✅ Command succeeded")
                return True
            else:
                print(f"❌ Command failed with exit code {result.returncode}")
                print(f"STDERR: {result.stderr}")
                return False
                
    except Exception as e:
        print(f"❌ Exception running command: {e}")
        return False


def main():
    """Main validation function."""
    print("🚀 Validating OpenID4VP Make Commands")
    print("=" * 50)
    
    success_count = 0
    total_count = 0
    
    # Test commands that should succeed
    success_tests = [
        ("make test-openid4vp-collect", "Test collection of OpenID4VP tests"),
        ("make test-openid4vp-setup", "OpenID4VP environment setup"),
        ("make help | grep -A 20 OpenID4VP", "Help documentation for OpenID4VP commands"),
    ]
    
    # Test commands that should fail gracefully (due to missing services)
    failure_tests = [
        ("make test-openid4vp-quick", "Quick OpenID4VP tests (expected to fail without services)"),
    ]
    
    # Run success tests
    for cmd, desc in success_tests:
        total_count += 1
        if run_command(cmd, desc):
            success_count += 1
    
    # Run failure tests (expecting graceful failures)
    for cmd, desc in failure_tests:
        total_count += 1
        if run_command(cmd, desc, expect_failure=True):
            success_count += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Validation Results: {success_count}/{total_count} tests passed")
    
    if success_count == total_count:
        print("✅ All Make command validations passed!")
        return 0
    else:
        print("❌ Some validations failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
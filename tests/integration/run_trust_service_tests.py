#!/usr/bin/env python3
"""
Test runner for trust service integration tests.
This script demonstrates the difference between basic and enhanced integration testing.
"""

import asyncio
import sys
import subprocess
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

project_root = Path(__file__).resolve().parents[2]

async def run_basic_test():
    """Run the basic integration test (original version)."""
    print("🔧 Running Basic Integration Test (with PKD service dependency)")
    print("="*70)
    
    basic_test_path = project_root / "tests" / "integration" / "test_trust_service_ml.py"
    
    try:
        result = subprocess.run(
            [sys.executable, str(basic_test_path)],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        print("STDOUT:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ Basic test failed to run: {e}")
        return False

async def run_enhanced_test():
    """Run the enhanced integration test (with mocked PKD service)."""
    print("\n🚀 Running Enhanced Integration Test (with mocked PKD service)")
    print("="*70)
    
    enhanced_test_path = project_root / "tests" / "integration" / "test_enhanced_trust_service.py"
    
    try:
        result = subprocess.run(
            [sys.executable, str(enhanced_test_path)],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        print("STDOUT:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ Enhanced test failed to run: {e}")
        return False

async def main():
    """Run both integration tests and compare results."""
    print("🔒 Trust Service Integration Test Comparison")
    print("This demonstrates the value of mocked PKD services for complete testing")
    print("="*70)
    
    # Run basic test
    basic_success = await run_basic_test()
    
    # Run enhanced test
    enhanced_success = await run_enhanced_test()
    
    # Summary
    print("\n" + "="*70)
    print("📊 INTEGRATION TEST COMPARISON SUMMARY")
    print("="*70)
    
    print(f"🔧 Basic Test (PKD Dependencies):     {'✅ PASS' if basic_success else '❌ FAIL'}")
    print(f"🚀 Enhanced Test (Mocked PKD):        {'✅ PASS' if enhanced_success else '❌ FAIL'}")
    
    print("\n📋 Key Differences:")
    print("   • Basic Test:    Limited by real PKD service availability")
    print("   • Enhanced Test: Full workflow testing with mocked components")
    print("   • Enhanced Test: ASN.1 parsing, trust validation, upload simulation")
    print("   • Enhanced Test: End-to-end workflow verification")
    
    if enhanced_success:
        print("\n🎉 RECOMMENDATION: Use enhanced test for complete trust service validation")
        print("   The mocked PKD service enables comprehensive testing without external dependencies")
    else:
        print("\n🔧 Further development needed on enhanced test framework")
    
    print("="*70)
    
    return 0 if (basic_success or enhanced_success) else 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
#!/usr/bin/env python3
"""
Demo script showing DRY synthetic data generation and usage

This demonstrates the consolidated approach to synthetic data generation
that replaces the previous scattered generator scripts.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)


async def demo_basic_generation():
    """Demo basic synthetic data generation."""
    print("\n🔧 DEMO: Basic Synthetic Data Generation")
    print("=" * 50)
    
    from scripts.generate_synthetic_data import SyntheticDataGenerator
    
    # Create generator
    output_dir = Path("./demo_data/basic")
    generator = SyntheticDataGenerator(output_dir, database_insert=False)
    
    try:
        await generator.initialize()
        
        # Generate small test dataset
        data = await generator.generate_all_data(
            countries=["USA", "CAN", "GBR"],
            passport_count=10,
            mdl_count=5,
            mdoc_count=5,
            dtc_count=3
        )
        
        await generator.save_data(data, "json")
        
        print(f"✅ Generated synthetic data in: {output_dir}")
        print(f"   • {len(data['passports'])} passports")
        print(f"   • {len(data['certificates']['csca'])} CSCA certificates")
        print(f"   • {len(data['certificates']['ds'])} DS certificates")
        print(f"   • {len(data['certificates']['masterLists'])} master lists")
        
    finally:
        await generator.close()


async def demo_trust_service_integration():
    """Demo trust service database integration."""
    print("\n💾 DEMO: Trust Service Database Integration")
    print("=" * 50)
    
    from scripts.generate_synthetic_data import SyntheticDataGenerator, TRUST_SERVICE_AVAILABLE
    
    if not TRUST_SERVICE_AVAILABLE:
        print("⚠️  Trust service not available - skipping database demo")
        return
    
    # Create generator with database integration
    output_dir = Path("./demo_data/trust_service")
    generator = SyntheticDataGenerator(output_dir, database_insert=True)
    
    try:
        await generator.initialize()
        
        if not generator.trust_db_manager:
            print("⚠️  Trust database not available - skipping database demo")
            return
        
        # Generate trust service focused data
        data = await generator.generate_all_data(
            countries=["USA", "FRA"],
            passport_count=5,  # Minimal passports
            mdl_count=0,
            mdoc_count=0,
            dtc_count=0
        )
        
        await generator.save_data(data, "json")
        await generator.insert_trust_service_data(data)
        
        print(f"✅ Generated and inserted trust service data:")
        print(f"   • {len(data['certificates']['masterLists'])} master lists inserted")
        print(f"   • {len(data['certificates']['csca'])} trust anchors inserted")
        print(f"   • {len(data['certificates']['ds'])} DS certificates inserted")
        print(f"   • {len(data['certificates']['crls'])} CRLs inserted")
        
    except Exception as e:
        print(f"❌ Database demo failed: {e}")
        
    finally:
        await generator.close()


async def demo_integration_testing():
    """Demo integration testing with synthetic data."""
    print("\n🧪 DEMO: Integration Testing with Synthetic Data")
    print("=" * 50)
    
    from scripts.test_synthetic_integration import SyntheticDataTester
    from scripts.generate_synthetic_data import SyntheticDataGenerator
    
    # Generate test data
    output_dir = Path("./demo_data/integration_test")
    generator = SyntheticDataGenerator(output_dir, database_insert=False)
    
    try:
        await generator.initialize()
        
        # Generate data for testing
        data = await generator.generate_all_data(
            countries=["USA", "GBR"],
            passport_count=15,
            mdl_count=5,
            mdoc_count=5,
            dtc_count=3
        )
        
        await generator.save_data(data, "json")
        
        # Run validation tests
        tester = SyntheticDataTester(output_dir)
        await tester.run_comprehensive_tests()
        
        # Show results
        print("✅ Integration tests completed:")
        for result in tester.test_results:
            test_name = result["test_name"]
            if "error" in result:
                print(f"   ❌ {test_name}: {result['error']}")
            else:
                print(f"   ✅ {test_name}: passed")
        
    finally:
        await generator.close()


async def main():
    """Run all demos."""
    logging.basicConfig(level=logging.INFO)
    
    print("🎯 MARTY SYNTHETIC DATA GENERATOR DEMO")
    print("=" * 60)
    print("This demo shows the consolidated DRY approach to synthetic data generation")
    print("that replaces multiple scattered generator scripts.")
    print()
    
    try:
        # Demo 1: Basic generation
        await demo_basic_generation()
        
        # Demo 2: Trust service integration  
        await demo_trust_service_integration()
        
        # Demo 3: Integration testing
        await demo_integration_testing()
        
        print("\n🎉 ALL DEMOS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("Key benefits of the consolidated approach:")
        print("• DRY: Single script replaces multiple generators")
        print("• Comprehensive: Covers all data types (passports, certificates, credentials)")
        print("• Database integration: Direct trust service database insertion")
        print("• Validation: Built-in data consistency checking")
        print("• Extensible: Easy to add new data types and validation rules")
        print()
        print("Usage examples:")
        print("# Generate standard dataset:")
        print("python scripts/generate_synthetic_data.py --countries 10 --passports 100")
        print()
        print("# Generate with database insertion:")
        print("python scripts/generate_synthetic_data.py --database-insert")
        print()
        print("# Run integration tests:")
        print("python scripts/test_synthetic_integration.py")
        
    except Exception:
        logger.exception("Demo failed")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
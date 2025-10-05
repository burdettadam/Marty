#!/usr/bin/env python3
"""
Simple test script for verifying per-service database connections.

This script tests that each service database exists and is accessible.
"""

import asyncio
import sys
import asyncpg

# Test database configuration
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "user": "dev_user",
    "password": "dev_password"
}

# List of service databases to test
SERVICE_DATABASES = [
    "marty_document_signer",
    "marty_csca", 
    "marty_pkd",
    "marty_passport_engine",
    "marty_dev"
]

async def test_database_connection(database_name: str) -> bool:
    """Test connection to a specific database."""
    try:
        conn = await asyncpg.connect(
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            database=database_name
        )
        
        # Test basic query
        version = await conn.fetchval("SELECT version()")
        print(f"✅ {database_name}: Connected successfully")
        print(f"   PostgreSQL version: {version.split(',')[0]}")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ {database_name}: Connection failed - {e}")
        return False

async def test_database_setup():
    """Test all service databases."""
    print("Testing database per service setup...")
    print("=" * 50)
    
    results = {}
    
    for db_name in SERVICE_DATABASES:
        results[db_name] = await test_database_connection(db_name)
        print()
    
    print("=" * 50)
    print("Summary:")
    
    success_count = sum(results.values())
    total_count = len(results)
    
    for db_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {db_name}: {status}")
    
    print(f"\nOverall: {success_count}/{total_count} databases accessible")
    
    if success_count == total_count:
        print("🎉 All database connections successful!")
        return True
    else:
        print("⚠️  Some database connections failed")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_database_setup())
    sys.exit(0 if success else 1)
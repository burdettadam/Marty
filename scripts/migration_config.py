"""
Simple configuration utilities for database migrations.
"""

import os

def get_database_url(service_name: str) -> str:
    """Get database URL for a specific service."""
    
    # Default test configuration
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    user = os.getenv("DB_USER", "dev_user")
    password = os.getenv("DB_PASSWORD", "dev_password")
    
    # Map service names to database names
    db_mapping = {
        "document_signer": "marty_document_signer",
        "csca": "marty_csca",
        "pkd_service": "marty_pkd",
        "passport_engine": "marty_passport_engine"
    }
    
    database = db_mapping.get(service_name, f"marty_{service_name}")
    
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{database}"
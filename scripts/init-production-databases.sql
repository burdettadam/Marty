-- Initialize production databases for per-service database architecture

-- Create databases for each service (production environment)
CREATE DATABASE marty_document_signer_production OWNER ${DB_USER};
CREATE DATABASE marty_csca_production OWNER ${DB_USER};
CREATE DATABASE marty_pkd_production OWNER ${DB_USER};
CREATE DATABASE marty_passport_engine_production OWNER ${DB_USER};

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE marty_document_signer_production TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE marty_csca_production TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE marty_pkd_production TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE marty_passport_engine_production TO ${DB_USER};
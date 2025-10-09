-- Initialize test databases and user for per-service database testing

-- Create application user
CREATE USER dev_user WITH PASSWORD 'dev_password';
ALTER USER dev_user CREATEDB;

-- Create databases for each service
CREATE DATABASE marty_document_signer OWNER dev_user;
CREATE DATABASE marty_csca OWNER dev_user;
CREATE DATABASE marty_pkd OWNER dev_user;
CREATE DATABASE marty_passport_engine OWNER dev_user;

-- Create default database for backward compatibility
CREATE DATABASE marty_dev OWNER dev_user;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE marty_document_signer TO dev_user;
GRANT ALL PRIVILEGES ON DATABASE marty_csca TO dev_user;
GRANT ALL PRIVILEGES ON DATABASE marty_pkd TO dev_user;
GRANT ALL PRIVILEGES ON DATABASE marty_passport_engine TO dev_user;
GRANT ALL PRIVILEGES ON DATABASE marty_dev TO dev_user;

-- Initialize trust_svc schema and data
-- This is automatically executed when PostgreSQL starts

-- Read and execute the schema file
\i /app/src/trust_svc/database/schema.sql

-- Read and execute the sample data file
\i /app/src/trust_svc/database/sample_data.sql

-- Grant necessary permissions
GRANT USAGE ON SCHEMA trust_svc TO martyuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA trust_svc TO martyuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA trust_svc TO martyuser;
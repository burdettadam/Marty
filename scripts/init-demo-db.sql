-- Demo Database Initialization Script
-- This script sets up the PostgreSQL database for the Marty demo environment
-- It creates multiple databases and schemas as needed

-- Create databases for different services (if they don't exist)
SELECT 'CREATE DATABASE trust_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'trust_db')\gexec

SELECT 'CREATE DATABASE credentials_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'credentials_db')\gexec

SELECT 'CREATE DATABASE audit_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'audit_db')\gexec

-- Connect to the main database and create demo schema
\c martydb;

-- Create demo schema for sample data
CREATE SCHEMA IF NOT EXISTS demo;

-- Set search path to include demo schema
SET search_path TO demo, public;

-- Create demo tables for sample data
CREATE TABLE IF NOT EXISTS demo.sample_passports (
    id SERIAL PRIMARY KEY,
    document_number VARCHAR(50) UNIQUE NOT NULL,
    issuing_country VARCHAR(3) NOT NULL,
    holder_name VARCHAR(255) NOT NULL,
    birth_date DATE NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS demo.sample_mdls (
    id SERIAL PRIMARY KEY,
    license_number VARCHAR(50) UNIQUE NOT NULL,
    issuing_state VARCHAR(50) NOT NULL,
    holder_name VARCHAR(255) NOT NULL,
    birth_date DATE NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    license_class VARCHAR(10) NOT NULL,
    restrictions TEXT,
    endorsements TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS demo.sample_mdocs (
    id SERIAL PRIMARY KEY,
    document_id VARCHAR(50) UNIQUE NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    issuer VARCHAR(100) NOT NULL,
    holder_name VARCHAR(255) NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS demo.issued_credentials (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(100) UNIQUE NOT NULL,
    credential_type VARCHAR(50) NOT NULL,
    subject_id VARCHAR(100) NOT NULL,
    issuer_id VARCHAR(100) NOT NULL,
    issue_date TIMESTAMP NOT NULL,
    expiry_date TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    credential_data JSONB,
    selective_disclosures JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS demo.verification_logs (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(100),
    verifier_id VARCHAR(100),
    verification_time TIMESTAMP DEFAULT NOW(),
    verification_result VARCHAR(20),
    verification_details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sample_passports_country ON demo.sample_passports(issuing_country);
CREATE INDEX IF NOT EXISTS idx_sample_passports_holder ON demo.sample_passports(holder_name);
CREATE INDEX IF NOT EXISTS idx_sample_mdls_state ON demo.sample_mdls(issuing_state);
CREATE INDEX IF NOT EXISTS idx_sample_mdls_holder ON demo.sample_mdls(holder_name);
CREATE INDEX IF NOT EXISTS idx_issued_credentials_type ON demo.issued_credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_issued_credentials_subject ON demo.issued_credentials(subject_id);
CREATE INDEX IF NOT EXISTS idx_verification_logs_credential ON demo.verification_logs(credential_id);
CREATE INDEX IF NOT EXISTS idx_verification_logs_time ON demo.verification_logs(verification_time);

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers to automatically update the updated_at column
CREATE TRIGGER update_sample_passports_updated_at BEFORE UPDATE ON demo.sample_passports FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sample_mdls_updated_at BEFORE UPDATE ON demo.sample_mdls FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sample_mdocs_updated_at BEFORE UPDATE ON demo.sample_mdocs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_issued_credentials_updated_at BEFORE UPDATE ON demo.issued_credentials FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions to the demo user
GRANT ALL PRIVILEGES ON SCHEMA demo TO martyuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA demo TO martyuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA demo TO martyuser;

-- Connect to trust_db and set up trust-related tables
\c trust_db;

CREATE SCHEMA IF NOT EXISTS trust_data;
SET search_path TO trust_data, public;

CREATE TABLE IF NOT EXISTS trust_data.trust_anchors (
    id SERIAL PRIMARY KEY,
    anchor_id VARCHAR(100) UNIQUE NOT NULL,
    country_code VARCHAR(3) NOT NULL,
    organization VARCHAR(255) NOT NULL,
    certificate_data TEXT NOT NULL,
    validity_start DATE NOT NULL,
    validity_end DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_data.csca_certificates (
    id SERIAL PRIMARY KEY,
    certificate_id VARCHAR(100) UNIQUE NOT NULL,
    country_code VARCHAR(3) NOT NULL,
    issuer VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    serial_number VARCHAR(100) NOT NULL,
    certificate_data TEXT NOT NULL,
    validity_start DATE NOT NULL,
    validity_end DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    trust_anchor_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (trust_anchor_id) REFERENCES trust_data.trust_anchors(anchor_id)
);

GRANT ALL PRIVILEGES ON SCHEMA trust_data TO martyuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA trust_data TO martyuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA trust_data TO martyuser;

-- Connect to credentials_db and set up credential storage
\c credentials_db;

CREATE SCHEMA IF NOT EXISTS credentials;
SET search_path TO credentials, public;

CREATE TABLE IF NOT EXISTS credentials.issued_credentials (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(100) UNIQUE NOT NULL,
    credential_type VARCHAR(50) NOT NULL,
    subject_did VARCHAR(255) NOT NULL,
    issuer_did VARCHAR(255) NOT NULL,
    issue_date TIMESTAMP NOT NULL,
    expiry_date TIMESTAMP,
    revocation_date TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    credential_data JSONB NOT NULL,
    proof_data JSONB,
    selective_disclosure_data JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credentials.revocation_registry (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(100) NOT NULL,
    revocation_reason VARCHAR(100),
    revocation_date TIMESTAMP NOT NULL,
    revoked_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (credential_id) REFERENCES credentials.issued_credentials(credential_id)
);

GRANT ALL PRIVILEGES ON SCHEMA credentials TO martyuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA credentials TO martyuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA credentials TO martyuser;

-- Connect to audit_db and set up audit logging
\c audit_db;

CREATE SCHEMA IF NOT EXISTS audit;
SET search_path TO audit, public;

CREATE TABLE IF NOT EXISTS audit.system_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    service_name VARCHAR(50) NOT NULL,
    user_id VARCHAR(100),
    resource_id VARCHAR(100),
    action VARCHAR(50) NOT NULL,
    outcome VARCHAR(20) NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit.credential_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    credential_id VARCHAR(100) NOT NULL,
    subject_id VARCHAR(100),
    verifier_id VARCHAR(100),
    action VARCHAR(50) NOT NULL,
    outcome VARCHAR(20) NOT NULL,
    verification_details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for audit tables
CREATE INDEX IF NOT EXISTS idx_system_events_type ON audit.system_events(event_type);
CREATE INDEX IF NOT EXISTS idx_system_events_service ON audit.system_events(service_name);
CREATE INDEX IF NOT EXISTS idx_system_events_time ON audit.system_events(created_at);
CREATE INDEX IF NOT EXISTS idx_credential_events_type ON audit.credential_events(event_type);
CREATE INDEX IF NOT EXISTS idx_credential_events_credential ON audit.credential_events(credential_id);
CREATE INDEX IF NOT EXISTS idx_credential_events_time ON audit.credential_events(created_at);

GRANT ALL PRIVILEGES ON SCHEMA audit TO martyuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO martyuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO martyuser;

-- Return to the main database
\c martydb;

-- Insert some initial sample data for demo purposes
INSERT INTO demo.sample_passports (document_number, issuing_country, holder_name, birth_date, issue_date, expiry_date) VALUES
('P123456789', 'USA', 'John Doe', '1990-01-15', '2023-01-01', '2033-01-01'),
('P987654321', 'CAN', 'Jane Smith', '1985-06-22', '2022-03-15', '2032-03-15'),
('P456789123', 'GBR', 'Bob Wilson', '1978-12-03', '2021-07-10', '2031-07-10'),
('P789123456', 'AUS', 'Alice Brown', '1992-09-18', '2023-05-20', '2033-05-20'),
('P321654987', 'DEU', 'Hans Mueller', '1980-04-25', '2022-11-08', '2032-11-08')
ON CONFLICT (document_number) DO NOTHING;

INSERT INTO demo.sample_mdls (license_number, issuing_state, holder_name, birth_date, issue_date, expiry_date, license_class, restrictions, endorsements) VALUES
('DL123456789', 'California', 'John Doe', '1990-01-15', '2020-01-15', '2025-01-15', 'C', 'None', 'None'),
('DL987654321', 'Texas', 'Jane Smith', '1985-06-22', '2019-06-22', '2024-06-22', 'C', 'Corrective Lenses', 'None'),
('DL456789123', 'New York', 'Bob Wilson', '1978-12-03', '2021-12-03', '2026-12-03', 'CDL', 'None', 'Hazmat'),
('DL789123456', 'Florida', 'Alice Brown', '1992-09-18', '2022-09-18', '2027-09-18', 'C', 'None', 'Motorcycle'),
('DL321654987', 'Nevada', 'Charlie Davis', '1987-03-12', '2020-03-12', '2025-03-12', 'M', 'None', 'None')
ON CONFLICT (license_number) DO NOTHING;

INSERT INTO demo.sample_mdocs (document_id, document_type, issuer, holder_name, issue_date, expiry_date, status, metadata) VALUES
('MDOC001', 'university_degree', 'University of California', 'John Doe', '2012-06-15', '2050-06-15', 'active', '{"degree": "Bachelor of Science", "major": "Computer Science", "gpa": "3.8"}'),
('MDOC002', 'professional_license', 'California Medical Board', 'Jane Smith', '2010-03-20', '2025-03-20', 'active', '{"license_type": "Medical Doctor", "specialization": "Internal Medicine", "license_number": "MD123456"}'),
('MDOC003', 'employment_credential', 'Tech Corp Inc', 'Bob Wilson', '2021-01-10', '2024-01-10', 'active', '{"position": "Senior Software Engineer", "clearance_level": "Secret", "employee_id": "EMP789"}'),
('MDOC004', 'insurance_credential', 'Health Insurance Co', 'Alice Brown', '2023-01-01', '2024-01-01', 'active', '{"policy_number": "INS456789", "coverage_type": "Premium", "member_id": "MEM123"}'),
('MDOC005', 'certification', 'Professional Certification Board', 'Charlie Davis', '2022-08-15', '2025-08-15', 'active', '{"certification": "Project Management Professional", "certification_id": "PMP987654", "renewal_required": true}')
ON CONFLICT (document_id) DO NOTHING;

-- Log that the database initialization is complete
INSERT INTO demo.verification_logs (credential_id, verifier_id, verification_result, verification_details) VALUES
('SYSTEM', 'DATABASE_INIT', 'success', '{"message": "Demo database initialization completed successfully", "timestamp": "' || NOW() || '"}');

COMMIT;
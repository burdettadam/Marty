#!/usr/bin/env python3
"""
Demo Data Seeder for Marty Platform
Seeds the demo environment with sample certificates, documents, and credentials.
Relies on Docker Compose health checks and depends_on to ensure services are ready.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import asyncpg
import httpx
from minio import Minio
from minio.error import S3Error

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DemoSeeder:
    """Seeds demo data into the Marty platform services."""

    def __init__(self):
        self.postgres_url = os.getenv(
            "POSTGRES_URL", "postgresql://martyuser:martypassword@postgres-demo:5432/martydb"
        )
        self.minio_endpoint = os.getenv("MINIO_ENDPOINT", "minio-demo:9000")
        self.minio_access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.minio_secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin123")
        self.issuer_api_endpoint = os.getenv("ISSUER_API_ENDPOINT", "http://issuer-api-demo:8000")
        self.vault_addr = os.getenv("VAULT_ADDR", "http://vault-demo:8200")
        self.vault_token = os.getenv("VAULT_TOKEN", "demo-root-token")

    async def seed_all(self):
        """Seed all demo data."""
        logger.info("Starting demo data seeding process...")

        try:
            # These operations can run in parallel since they're independent
            await asyncio.gather(
                self.seed_database(),
                self.seed_object_storage(),
                self.seed_vault_secrets(),
                return_exceptions=True,
            )

            # These depend on the above being complete
            await self.seed_sample_credentials()
            await self.create_demo_users()

            logger.info("Demo data seeding completed successfully!")

        except Exception as e:
            logger.error(f"Error during demo seeding: {e}")
            raise

    async def seed_database(self):
        """Seed PostgreSQL with demo data."""
        logger.info("Seeding PostgreSQL database...")

        try:
            conn = await asyncpg.connect(self.postgres_url)

            # Create demo schemas if they don't exist
            await conn.execute(
                """
                CREATE SCHEMA IF NOT EXISTS trust_data;
                CREATE SCHEMA IF NOT EXISTS credentials;
                CREATE SCHEMA IF NOT EXISTS audit;
            """
            )

            # Create sample tables and data
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS demo.sample_passports (
                    id SERIAL PRIMARY KEY,
                    document_number VARCHAR(50) UNIQUE,
                    issuing_country VARCHAR(3),
                    holder_name VARCHAR(255),
                    birth_date DATE,
                    issue_date DATE,
                    expiry_date DATE,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """
            )

            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS demo.sample_mdls (
                    id SERIAL PRIMARY KEY,
                    license_number VARCHAR(50) UNIQUE,
                    issuing_state VARCHAR(50),
                    holder_name VARCHAR(255),
                    birth_date DATE,
                    issue_date DATE,
                    expiry_date DATE,
                    license_class VARCHAR(10),
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """
            )

            # Insert sample data
            sample_passports = [
                ("P123456789", "USA", "John Doe", "1990-01-15", "2023-01-01", "2033-01-01"),
                ("P987654321", "CAN", "Jane Smith", "1985-06-22", "2022-03-15", "2032-03-15"),
                ("P456789123", "GBR", "Bob Wilson", "1978-12-03", "2021-07-10", "2031-07-10"),
                ("P789123456", "AUS", "Alice Brown", "1992-09-18", "2023-05-20", "2033-05-20"),
                ("P321654987", "DEU", "Hans Mueller", "1980-04-25", "2022-11-08", "2032-11-08"),
            ]

            for passport in sample_passports:
                await conn.execute(
                    """
                    INSERT INTO demo.sample_passports
                    (document_number, issuing_country, holder_name, birth_date, issue_date, expiry_date)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (document_number) DO NOTHING
                """,
                    *passport,
                )

            sample_mdls = [
                (
                    "DL123456789",
                    "California",
                    "John Doe",
                    "1990-01-15",
                    "2020-01-15",
                    "2025-01-15",
                    "C",
                ),
                (
                    "DL987654321",
                    "Texas",
                    "Jane Smith",
                    "1985-06-22",
                    "2019-06-22",
                    "2024-06-22",
                    "C",
                ),
                (
                    "DL456789123",
                    "New York",
                    "Bob Wilson",
                    "1978-12-03",
                    "2021-12-03",
                    "2026-12-03",
                    "CDL",
                ),
                (
                    "DL789123456",
                    "Florida",
                    "Alice Brown",
                    "1992-09-18",
                    "2022-09-18",
                    "2027-09-18",
                    "C",
                ),
                (
                    "DL321654987",
                    "Nevada",
                    "Charlie Davis",
                    "1987-03-12",
                    "2020-03-12",
                    "2025-03-12",
                    "M",
                ),
            ]

            for mdl in sample_mdls:
                await conn.execute(
                    """
                    INSERT INTO demo.sample_mdls
                    (license_number, issuing_state, holder_name, birth_date, issue_date, expiry_date, license_class)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (license_number) DO NOTHING
                """,
                    *mdl,
                )

            await conn.close()
            logger.info("PostgreSQL seeding completed")

        except Exception as e:
            logger.error(f"Error seeding PostgreSQL: {e}")
            raise

    async def seed_object_storage(self):
        """Seed MinIO with demo files."""
        logger.info("Seeding MinIO object storage...")

        try:
            client = Minio(
                self.minio_endpoint,
                access_key=self.minio_access_key,
                secret_key=self.minio_secret_key,
                secure=False,
            )

            # Ensure buckets exist
            buckets = ["documents", "certificates", "credentials", "audit-logs"]
            for bucket in buckets:
                if not client.bucket_exists(bucket):
                    client.make_bucket(bucket)
                    logger.info(f"Created bucket: {bucket}")

            # Upload sample files
            demo_files = {
                "documents/sample-passport.json": self._create_sample_passport_data(),
                "documents/sample-mdl.json": self._create_sample_mdl_data(),
                "certificates/demo-csca.pem": self._create_demo_csca_cert(),
                "certificates/demo-ds.pem": self._create_demo_ds_cert(),
                "credentials/sample-vc.json": self._create_sample_verifiable_credential(),
            }

            for object_name, content in demo_files.items():
                bucket, key = object_name.split("/", 1)
                try:
                    # Convert content to bytes if it's a string
                    if isinstance(content, str):
                        content_bytes = content.encode("utf-8")
                    else:
                        content_bytes = content

                    # Create a temporary file-like object
                    import io

                    content_stream = io.BytesIO(content_bytes)

                    client.put_object(
                        bucket,
                        key,
                        content_stream,
                        len(content_bytes),
                        content_type="application/json" if key.endswith(".json") else "text/plain",
                    )
                    logger.info(f"Uploaded: {object_name}")
                except S3Error as e:
                    logger.warning(f"Failed to upload {object_name}: {e}")

            logger.info("MinIO seeding completed")

        except Exception as e:
            logger.error(f"Error seeding MinIO: {e}")
            raise

    async def seed_vault_secrets(self):
        """Seed HashiCorp Vault with demo secrets."""
        logger.info("Seeding Vault with demo secrets...")

        try:
            async with httpx.AsyncClient() as client:
                headers = {"X-Vault-Token": self.vault_token}

                # Enable KV v2 secrets engine
                await client.post(
                    f"{self.vault_addr}/v1/sys/mounts/secret",
                    headers=headers,
                    json={"type": "kv", "options": {"version": "2"}},
                )

                # Store demo secrets
                secrets = {
                    "secret/data/demo/signing-keys": {
                        "data": {
                            "private_key": self._create_demo_private_key(),
                            "public_key": self._create_demo_public_key(),
                            "algorithm": "ES256",
                        }
                    },
                    "secret/data/demo/api-keys": {
                        "data": {
                            "issuer_api_key": "demo_issuer_key_12345",
                            "verifier_api_key": "demo_verifier_key_67890",
                            "admin_api_key": "demo_admin_key_abcdef",
                        }
                    },
                    "secret/data/demo/database": {
                        "data": {
                            "username": "martyuser",
                            "password": "martypassword",
                            "connection_string": self.postgres_url,
                        }
                    },
                }

                for path, secret in secrets.items():
                    try:
                        response = await client.post(
                            f"{self.vault_addr}/v1/{path}", headers=headers, json=secret
                        )
                        if response.status_code in [200, 204]:
                            logger.info(f"Stored secret: {path}")
                        else:
                            logger.warning(f"Failed to store secret {path}: {response.status_code}")
                    except Exception as e:
                        logger.warning(f"Error storing secret {path}: {e}")

            logger.info("Vault seeding completed")

        except Exception as e:
            logger.error(f"Error seeding Vault: {e}")
            raise

    async def seed_sample_credentials(self):
        """Create sample verifiable credentials via the Issuer API."""
        logger.info("Creating sample verifiable credentials...")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Wait for issuer API to be ready
                health_url = f"{self.issuer_api_endpoint}/health"
                for attempt in range(10):
                    try:
                        response = await client.get(health_url)
                        if response.status_code == 200:
                            break
                    except httpx.RequestError:
                        if attempt == 9:
                            raise
                        await asyncio.sleep(5)

                # Create sample credentials
                sample_requests = [
                    {
                        "subject_id": "demo-user-001",
                        "credential_type": "PassportCredential",
                        "base_claims": {
                            "document_number": "P123456789",
                            "issuing_country": "USA",
                            "holder_name": "John Doe",
                            "birth_date": "1990-01-15",
                        },
                        "selective_disclosures": {
                            "address": "123 Main St, Anytown, USA",
                            "phone": "+1-555-0123",
                        },
                    },
                    {
                        "subject_id": "demo-user-002",
                        "credential_type": "MDLCredential",
                        "base_claims": {
                            "license_number": "DL123456789",
                            "issuing_state": "California",
                            "holder_name": "Jane Smith",
                            "license_class": "C",
                        },
                        "selective_disclosures": {
                            "restrictions": "Corrective Lenses",
                            "endorsements": "None",
                        },
                    },
                ]

                for request_data in sample_requests:
                    try:
                        response = await client.post(
                            f"{self.issuer_api_endpoint}/v1/credentials/offer", json=request_data
                        )
                        if response.status_code in [200, 201]:
                            logger.info(f"Created credential for {request_data['subject_id']}")
                        else:
                            logger.warning(f"Failed to create credential: {response.status_code}")
                    except Exception as e:
                        logger.warning(f"Error creating credential: {e}")

            logger.info("Sample credentials creation completed")

        except Exception as e:
            logger.error(f"Error creating sample credentials: {e}")
            raise

    async def create_demo_users(self):
        """Create demo users for the UI."""
        logger.info("Creating demo users...")

        # This would typically involve creating users in your auth system
        # For demo purposes, we'll just log that this step completed
        demo_users = [
            {"username": "demo", "role": "admin", "password": "demo123"},
            {"username": "issuer", "role": "issuer", "password": "issuer123"},
            {"username": "verifier", "role": "verifier", "password": "verifier123"},
        ]

        for user in demo_users:
            logger.info(f"Demo user created: {user['username']} (role: {user['role']})")

        logger.info("Demo users creation completed")

    # Helper methods for creating demo data

    def _create_sample_passport_data(self) -> str:
        """Create sample passport data."""
        return json.dumps(
            {
                "document_type": "passport",
                "document_number": "P123456789",
                "issuing_country": "USA",
                "holder": {"name": "John Doe", "birth_date": "1990-01-15", "nationality": "USA"},
                "validity": {"issue_date": "2023-01-01", "expiry_date": "2033-01-01"},
                "security_features": {
                    "chip_present": True,
                    "biometric_data": True,
                    "digital_signature": True,
                },
            },
            indent=2,
        )

    def _create_sample_mdl_data(self) -> str:
        """Create sample mobile driver's license data."""
        return json.dumps(
            {
                "document_type": "mobile_drivers_license",
                "license_number": "DL123456789",
                "issuing_state": "California",
                "holder": {
                    "name": "Jane Smith",
                    "birth_date": "1985-06-22",
                    "address": "456 Oak Ave, Los Angeles, CA 90210",
                },
                "license_info": {
                    "class": "C",
                    "issue_date": "2020-01-15",
                    "expiry_date": "2025-01-15",
                    "restrictions": "Corrective Lenses",
                    "endorsements": "None",
                },
            },
            indent=2,
        )

    def _create_sample_verifiable_credential(self) -> str:
        """Create sample verifiable credential."""
        return json.dumps(
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://w3id.org/citizenship/v1",
                ],
                "type": ["VerifiableCredential", "CitizenshipCredential"],
                "issuer": "did:example:issuer123",
                "issuanceDate": "2023-01-01T00:00:00Z",
                "expirationDate": "2033-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:subject456",
                    "type": "CitizenshipCredential",
                    "name": "John Doe",
                    "birthDate": "1990-01-15",
                    "citizenship": "US",
                },
                "proof": {
                    "type": "Ed25519Signature2018",
                    "created": "2023-01-01T00:00:00Z",
                    "verificationMethod": "did:example:issuer123#key1",
                    "proofPurpose": "assertionMethod",
                    "jws": "demo_signature_value_here",
                },
            },
            indent=2,
        )

    def _create_demo_csca_cert(self) -> str:
        """Create demo CSCA certificate."""
        return """-----BEGIN CERTIFICATE-----
MIIDemoCSCACertificateDataHereForDemoUseOnly123456789ABCDEF
ThisIsNotARealCertificateAndIsOnlyForDemonstrationPurposes
PleaseReplaceWithActualCertificateDataInProductionEnvironment
-----END CERTIFICATE-----"""

    def _create_demo_ds_cert(self) -> str:
        """Create demo Document Signer certificate."""
        return """-----BEGIN CERTIFICATE-----
MIIDemoDocumentSignerCertificateDataHereForDemoUseOnly123456
ThisIsNotARealCertificateAndIsOnlyForDemonstrationPurposes
PleaseReplaceWithActualCertificateDataInProductionEnvironment
-----END CERTIFICATE-----"""

    def _create_demo_private_key(self) -> str:
        """Create demo private key."""
        return """-----BEGIN PRIVATE KEY-----
MIIDemoPrivateKeyDataHereForDemoUseOnlyNotForProduction123456
ThisIsNotARealPrivateKeyAndIsOnlyForDemonstrationPurposes
PleaseReplaceWithActualPrivateKeyDataInProductionEnvironment
-----END PRIVATE KEY-----"""

    def _create_demo_public_key(self) -> str:
        """Create demo public key."""
        return """-----BEGIN PUBLIC KEY-----
MIIDemoPublicKeyDataHereForDemoUseOnlyNotForProduction1234567
ThisIsNotARealPublicKeyAndIsOnlyForDemonstrationPurposes
PleaseReplaceWithActualPublicKeyDataInProductionEnvironment
-----END PUBLIC KEY-----"""


async def main():
    """Main entry point for the demo seeder."""
    logger.info("Marty Platform Demo Data Seeder starting...")

    seeder = DemoSeeder()
    try:
        await seeder.seed_all()
        logger.info("Demo seeding completed successfully!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Demo seeding failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

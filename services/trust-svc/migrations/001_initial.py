"""Initial database migration for Trust Service.

Revision ID: 001_initial
Revises:
Create Date: 2024-10-03 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial trust service database schema."""

    # Create trust_svc schema
    op.execute("CREATE SCHEMA IF NOT EXISTS trust_svc")

    # Create master_lists table
    op.create_table(
        "master_lists",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("country_code", sa.String(3), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("source_url", sa.Text),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("content_data", sa.LargeBinary, nullable=False),
        sa.Column("signature_data", sa.LargeBinary),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_by", sa.Text),
        sa.Column("metadata", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        schema="trust_svc",
    )

    # Create indexes for master_lists
    op.create_index(
        "idx_master_lists_country_version",
        "master_lists",
        ["country_code", "version"],
        schema="trust_svc",
    )
    op.create_index(
        "idx_master_lists_source_updated",
        "master_lists",
        ["source_type", "updated_at"],
        schema="trust_svc",
    )

    # Create cscas table
    op.create_table(
        "cscas",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("country_code", sa.String(3), nullable=False),
        sa.Column("certificate_hash", sa.String(64), nullable=False),
        sa.Column("certificate_data", sa.LargeBinary, nullable=False),
        sa.Column("subject_dn", sa.Text, nullable=False),
        sa.Column("issuer_dn", sa.Text, nullable=False),
        sa.Column("serial_number", sa.Text, nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_usage", postgresql.ARRAY(sa.String)),
        sa.Column("signature_algorithm", sa.String(50)),
        sa.Column("public_key_algorithm", sa.String(50)),
        sa.Column("trust_level", sa.String(20), server_default="standard"),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("immutable_flag", sa.Boolean, server_default="false"),
        sa.Column("master_list_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        schema="trust_svc",
    )

    # Create indexes and constraints for cscas
    op.create_unique_constraint(
        "uq_cscas_certificate_hash", "cscas", ["certificate_hash"], schema="trust_svc"
    )
    op.create_index(
        "idx_cscas_country_status", "cscas", ["country_code", "status"], schema="trust_svc"
    )
    op.create_index("idx_cscas_validity", "cscas", ["valid_from", "valid_to"], schema="trust_svc")
    op.create_foreign_key(
        "fk_cscas_master_list",
        "cscas",
        "master_lists",
        ["master_list_id"],
        ["id"],
        source_schema="trust_svc",
        referent_schema="trust_svc",
    )

    # Create dscs table
    op.create_table(
        "dscs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("country_code", sa.String(3), nullable=False),
        sa.Column("certificate_hash", sa.String(64), nullable=False),
        sa.Column("certificate_data", sa.LargeBinary, nullable=False),
        sa.Column("issuer_csca_id", postgresql.UUID(as_uuid=True)),
        sa.Column("subject_dn", sa.Text, nullable=False),
        sa.Column("issuer_dn", sa.Text, nullable=False),
        sa.Column("serial_number", sa.Text, nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_usage", postgresql.ARRAY(sa.String)),
        sa.Column("signature_algorithm", sa.String(50)),
        sa.Column("public_key_algorithm", sa.String(50)),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("revocation_reason", sa.String(50)),
        sa.Column("revocation_date", sa.DateTime(timezone=True)),
        sa.Column("master_list_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        schema="trust_svc",
    )

    # Create indexes and constraints for dscs
    op.create_unique_constraint(
        "uq_dscs_certificate_hash", "dscs", ["certificate_hash"], schema="trust_svc"
    )
    op.create_index(
        "idx_dscs_country_status", "dscs", ["country_code", "status"], schema="trust_svc"
    )
    op.create_index("idx_dscs_issuer", "dscs", ["issuer_csca_id"], schema="trust_svc")
    op.create_index("idx_dscs_validity", "dscs", ["valid_from", "valid_to"], schema="trust_svc")
    op.create_foreign_key(
        "fk_dscs_issuer_csca",
        "dscs",
        "cscas",
        ["issuer_csca_id"],
        ["id"],
        source_schema="trust_svc",
        referent_schema="trust_svc",
    )
    op.create_foreign_key(
        "fk_dscs_master_list",
        "dscs",
        "master_lists",
        ["master_list_id"],
        ["id"],
        source_schema="trust_svc",
        referent_schema="trust_svc",
    )

    # Create crls table
    op.create_table(
        "crls",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("country_code", sa.String(3), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("crl_data", sa.LargeBinary, nullable=False),
        sa.Column("issuer_dn", sa.Text, nullable=False),
        sa.Column("this_update", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_update", sa.DateTime(timezone=True)),
        sa.Column("signature_algorithm", sa.String(50)),
        sa.Column("extensions", postgresql.JSONB),
        sa.Column("revoked_certificates", postgresql.JSONB),
        sa.Column("source_url", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        schema="trust_svc",
    )

    # Create indexes for crls
    op.create_index(
        "idx_crls_issuer_country", "crls", ["issuer_dn", "country_code"], schema="trust_svc"
    )
    op.create_index("idx_crls_validity", "crls", ["this_update", "next_update"], schema="trust_svc")

    # Create sources table
    op.create_table(
        "sources",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("country_code", sa.String(3)),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("credentials", postgresql.JSONB),
        sa.Column("sync_interval", sa.Integer, server_default="3600"),
        sa.Column("last_sync", sa.DateTime(timezone=True)),
        sa.Column("last_success", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("retry_count", sa.Integer, server_default="0"),
        sa.Column("metadata", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        schema="trust_svc",
    )

    # Create indexes and constraints for sources
    op.create_unique_constraint(
        "uq_sources_type_country_url",
        "sources",
        ["source_type", "country_code", "url"],
        schema="trust_svc",
    )
    op.create_index(
        "idx_sources_type_status", "sources", ["source_type", "is_active"], schema="trust_svc"
    )

    # Create provenance table
    op.create_table(
        "provenance",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(20), nullable=False),
        sa.Column("changes", postgresql.JSONB),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text),
        sa.Column("metadata", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        schema="trust_svc",
    )

    # Create indexes for provenance
    op.create_index(
        "idx_provenance_entity", "provenance", ["entity_type", "entity_id"], schema="trust_svc"
    )
    op.create_index(
        "idx_provenance_source", "provenance", ["source_id", "created_at"], schema="trust_svc"
    )
    op.create_foreign_key(
        "fk_provenance_source",
        "provenance",
        "sources",
        ["source_id"],
        ["id"],
        source_schema="trust_svc",
        referent_schema="trust_svc",
    )

    # Create constraints for enum-like fields
    op.execute(
        "ALTER TABLE trust_svc.cscas ADD CONSTRAINT valid_trust_level CHECK (trust_level IN ('standard', 'high', 'emergency'))"
    )
    op.execute(
        "ALTER TABLE trust_svc.cscas ADD CONSTRAINT valid_status CHECK (status IN ('active', 'inactive', 'revoked'))"
    )
    op.execute(
        "ALTER TABLE trust_svc.dscs ADD CONSTRAINT valid_dsc_status CHECK (status IN ('active', 'inactive', 'revoked'))"
    )


def downgrade() -> None:
    """Drop trust service database schema."""

    # Drop all tables in reverse order due to foreign key constraints
    op.drop_table("provenance", schema="trust_svc")
    op.drop_table("sources", schema="trust_svc")
    op.drop_table("crls", schema="trust_svc")
    op.drop_table("dscs", schema="trust_svc")
    op.drop_table("cscas", schema="trust_svc")
    op.drop_table("master_lists", schema="trust_svc")

    # Drop schema
    op.execute("DROP SCHEMA IF EXISTS trust_svc CASCADE")

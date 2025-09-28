# Deployment Overview

This repository now supports running each gRPC microservice in a dedicated
container or process. Key points to remember when deploying:

- **Service Images**: Build a discrete image per service (e.g. `csca-service`,
  `document-signer`, `trust-anchor`, `pkd-service`). The entrypoint should
  execute `python -m src.apps.<service>` (for example `python -m src.apps.csca_service`).
- **Configuration**: Provide each container with the appropriate YAML config
  (`config/production.yaml`) and secrets for database credentials, object
  storage, message brokers, and TLS files. The new TLS settings live under
  `security.grpc_tls`.
- **Stateful Dependencies**: All certificate and DTC metadata is now stored via
  the shared `DatabaseManager` and object storage abstractions. Ensure Postgres,
  MinIO/S3, Kafka, and a key vault/KMS are provisioned and reachable.
- **PKD Synchronisation**: Run `python -m src.apps.pkd_service` as a standalone job or
  deployment. It will ingest trust anchors on demand via the `Sync` RPC and can
  optionally auto-sync when `PKD_AUTO_SYNC_INTERVAL` is set.
- **Trust Anchor Bootstrap**: The Trust Anchor service loads anchors from the
  PKD service on startup and publishes update events. Deploy both services in
  the same environment and enable event listeners to keep caches in sync.
- **TLS / mTLS**: Supply server and client certificates via the TLS config and
  mount them into each service. When `require_client_auth` is true, all
  inter-service gRPC calls must use client certificates.
- **Observability**: Enable health checks on `/grpc.health.v1.Health/Check` for
  each service. Forward service logs to your logging backend and collect
  metrics/event bus data to track certificate lifecycles.

With these pieces in place you can run each service independently and scale
horizontally according to workload.

## CI TLS / mTLS Smoke Test

The CI pipeline now exercises the secure gRPC path to catch certificate
regressions early:

- A new integration test (`tests/integration/test_tls_smoke.py`) generates an
  ephemeral CA, server, and client certificate bundle in-memory, starts a gRPC
  server using `configure_server_security`, and performs a health check through
  an mTLS-secured channel built with `build_client_credentials`.
- The test runs automatically via `pytest tests/integration` in the
  GitHub Actions workflow. It fails if server-side TLS cannot be configured or
  if the client handshake/Health RPC is rejected.
- Local developers can replicate the check with
  `PYTHONPATH=$(pwd)/src pytest tests/integration/test_tls_smoke.py`, which does
  not require any external TLS material.

The smoke test complements the existing unit coverage around the shared TLS
helpers and ensures both server and client code paths stay mTLS-ready.

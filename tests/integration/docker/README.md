# Docker Integration Tests

This directory contains Docker-based integration tests for the Marty passport system services. The tests use Docker Compose to run all system services and verify their functionality in an integrated environment.

## Directory Structure

```
docker/
├── configs/            # Test-specific configuration files
├── e2e/                # End-to-end tests that test multiple services together
│   └── test_passport_flow.py
├── helpers/            # Shared test utilities
│   └── base_docker_test.py
├── run_docker_tests.py # Main test runner script
└── services/           # Service-specific tests
    ├── csca-service/
    ├── document-signer/
    ├── inspection-system/
    ├── passport-engine/
    └── trust-anchor/
```

## Running Tests

You can run the Docker integration tests using the provided script:

```bash
# Run all tests
python tests/integration/docker/run_docker_tests.py

# Run only tests for a specific service
python tests/integration/docker/run_docker_tests.py --service=csca-service
python tests/integration/docker/run_docker_tests.py --service=document-signer
python tests/integration/docker/run_docker_tests.py --service=inspection-system
python tests/integration/docker/run_docker_tests.py --service=passport-engine
python tests/integration/docker/run_docker_tests.py --service=trust-anchor

# Run only end-to-end tests
python tests/integration/docker/run_docker_tests.py --e2e-only

# Don't clean up Docker services after tests (helpful for debugging)
python tests/integration/docker/run_docker_tests.py --no-cleanup

# Skip proto file compilation
python tests/integration/docker/run_docker_tests.py --skip-proto-compile

# Show more detailed test output
python tests/integration/docker/run_docker_tests.py --verbose
```

## Test Types

### Service-Specific Tests

Each service has its own set of tests to verify its functionality in isolation:

- **CSCA Service**: Tests the Certificate Authority functionality
- **Document Signer**: Tests document signing capabilities
- **Passport Engine**: Tests passport issuance and data generation
- **Inspection System**: Tests passport verification and validation
- **Trust Anchor**: Tests the trust verification system

### End-to-End Tests

End-to-end tests verify the entire system workflow from passport issuance to verification:

- **Passport Flow**: Tests the complete flow of passport processing and verification
- **Multiple Passport Processing**: Tests handling multiple passports in sequence

## Writing New Tests

To add new tests:

1. For service-specific tests, create a new file in the appropriate service directory:
   ```
   tests/integration/docker/services/{service-name}/test_feature_name.py
   ```

2. For end-to-end tests, create a new file in the e2e directory:
   ```
   tests/integration/docker/e2e/test_flow_name.py
   ```

3. Import and extend the base test class:
   ```python
   from tests.integration.docker.helpers.base_docker_test import BaseDockerIntegrationTest
   
   class MyTestCase(BaseDockerIntegrationTest):
       def test_my_feature(self):
           # Test code here
   ```

## Troubleshooting

If tests fail, check the following:

1. Make sure all services are running. Use `docker compose ps` to check status.
2. Check service logs: `docker compose logs service-name`
3. Verify data persistence directories are properly mounted.
4. Ensure proto files are compiled with the latest definitions.

Test logs are saved to `docker_integration_test.log` for detailed debugging.
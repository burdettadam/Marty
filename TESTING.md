# Testing Strategy for Marty

## Overview
This document describes the testing strategy for the Marty project, including unit, integration, end-to-end (E2E), and third-party integration tests. It also outlines best practices, coverage goals, and contribution guidelines.

---

## Test Types

### 1. Unit Tests
- **Purpose:** Validate individual modules, models, and utility functions in isolation.
- **Tools:** `pytest`, `unittest`, `pytest-depends`.
- **Features:**
  - Mocking for external dependencies and proto conflicts.
  - Data-driven tests for MRZ, DG1, SOD, DG14, DG15, ISO9796-2, key management, and certificate lifecycle.
  - Third-party test integration (ZeroPass/pymrtd, PassportEye, certvalidator).

### 2. Integration Tests
- **Purpose:** Test service-specific functionality in real Docker containers.
- **Tools:** Docker Compose, gRPC, `unittest`.
- **Features:**
  - Health checks, error handling, performance, and edge cases.
  - Shared base test class for Docker orchestration and utilities.

### 3. End-to-End (E2E) Tests
- **Purpose:** Validate full system workflows across multiple services.
- **Tools:** Docker Compose, gRPC, `unittest`.
- **Features:**
  - Simulates real-world workflows (passport issuance, verification, multiple processing).
  - Validates data persistence, inter-service communication, and system health.
  - Error handling and log collection for debugging.

### 4. Third-Party Integration Tests
- **Purpose:** Ensure compliance with international standards and external libraries.
- **Features:**
  - ICAO, ISO/IEC, PassportEye, certvalidator, OpenXPKI (planned).
  - Validates certificate, MRZ, OCR, PDF extraction, and registry logic.

---

## Running Tests

- **All tests:**
  ```bash
  make test
  ```
- **Unit tests:**
  ```bash
  make test-unit
  ```
- **Integration tests:**
  ```bash
  make test-integration
  ```
- **End-to-end tests:**
  ```bash
  make test-e2e
  ```
- **Certificate validation tests:**
  ```bash
  make test-cert-validator
  ```
- **Docker integration tests:**
  ```bash
  python tests/integration/docker/run_docker_tests.py [options]
  ```

---

## Coverage Goals
- Target >90% coverage for all services.
- Add missing integration tests for DTC Engine, mDoc Engine, and edge cases.
- Expand E2E tests for error handling, recovery, security, performance, and edge cases.
- Integrate coverage tools (e.g., `pytest-cov`) and CI reporting.

---

## Test Data Management
- Centralize and document test data sets for reproducibility.
- Add more diverse and realistic test data for E2E and integration tests.

---

## Continuous Integration (CI)
- Ensure all test types run in CI pipelines (unit, integration, E2E, third-party).
- Add Docker-based test runners to CI for integration/E2E tests.
- Enforce minimum coverage thresholds.

---

## Contributing Tests
- Add new unit tests in `tests/unit/`.
- Add new integration tests in `tests/integration/docker/services/{service-name}/`.
- Add new E2E tests in `tests/integration/docker/e2e/`.
- Use the shared base test class for Docker integration tests.
- Document new test data and scenarios.

---

## References
- See `README.md` for a summary and quick start.
- See service-specific docs for protocol and architecture details.

---

## Improvements Roadmap

## Action Plan for Proposed Improvements

### 1. Increase Test Coverage
- Audit current coverage using `pytest-cov` or `coverage.py`.
- Add missing unit and integration tests for:
  - DTC Engine
  - mDoc Engine
  - Edge cases in all services
- Track coverage in CI and enforce minimum thresholds (e.g., 90%).


### 2. Expand E2E Testing

- **Remove mocking in E2E tests:**
  - E2E tests should avoid mocking and instead use real stored data.
  - Inject test scenarios by preparing and loading data files or database entries before test execution.
  - Ensure all inter-service and workflow tests use actual data flows as in production.

- **Proposed New E2E Test Scenarios:**
  - **Error Handling & Recovery:**
    - Simulate service failures and verify system recovery (e.g., restart containers, network partition).
    - Test invalid input data and ensure proper error responses/logging.
    - Validate rollback and retry logic for failed transactions.
  - **Security Flows:**
    - Attempt to process documents with invalid signatures or tampered data.
    - Test unauthorized access to protected endpoints/services.
    - Simulate replay attacks and verify detection/prevention.
  - **Performance Under Load:**
    - Simulate concurrent requests to multiple services and measure response times.
    - Stress test with large data sets and high-frequency operations.
  - **Edge-Case Handling:**
    - Test boundary values for document fields (e.g., max/min lengths, unusual characters).
    - Process malformed or incomplete data and verify graceful handling.
    - Validate system behavior with missing or corrupted test data files.

- Document results and add new scenarios as they are implemented.

### 3. Automated Coverage Reporting
- Integrate `pytest-cov` with test runs:
  ```bash
  pytest --cov=src --cov-report=term-missing
  ```
- Add coverage badge/report to CI pipeline.
- Fail CI if coverage drops below threshold.

### 4. Test Data Management
- Centralize test data in `tests/data/` and document formats.
- Add more diverse and realistic test data for E2E and integration tests.
- Use fixtures and factories for generating test data.

### 5. Continuous Integration (CI)
- Ensure all test types run in CI (unit, integration, E2E, third-party).
- Add Docker-based test runners for integration/E2E tests in CI.
- Enforce coverage thresholds and report failures.

### 6. Documentation
- Keep `TESTING.md` up to date with new scenarios, coverage status, and contribution guidelines.
- Add examples for writing new tests and using test utilities.

### 7. OpenXPKI Integration
- Expand integration tests for OpenXPKI workflows.
- Document test scenarios and expected outcomes.

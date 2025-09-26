# E2E Testing Commands Summary
# =====================================

# Setup (run once):
make playwright-install

# Quick validation:
make test-e2e-smoke

# Full E2E test suite:
make test-e2e-ui

# Test against running UI (assumes UI at :8090):
make test-e2e-ui-existing

# Specific test categories:
make test-e2e-dashboard    # Dashboard tests
make test-e2e-passport     # Passport workflow
make test-e2e-mdl         # MDL workflow
make test-e2e-responsive  # Responsive design

# Generate HTML report:
make test-e2e-report

# Original orchestrator E2E tests:
make test-e2e

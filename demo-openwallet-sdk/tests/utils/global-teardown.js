// Global teardown for Playwright tests
async function globalTeardown() {
  console.log('🧹 Running E2E test teardown...');

  // Any cleanup needed after tests
  // For now, just log completion
  console.log('✅ E2E test teardown completed');
}

module.exports = globalTeardown;

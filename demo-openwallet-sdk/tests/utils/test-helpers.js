// Test utilities and helpers
const { expect } = require('@playwright/test');

class DemoTestHelpers {
  constructor(page) {
    this.page = page;
  }

  // Navigation helpers
  async navigateToTab(tabName) {
    await this.page.click(`text=${tabName}`);
    await this.page.waitForLoadState('networkidle');
  }

  async waitForPageLoad() {
    await this.page.waitForLoadState('domcontentloaded');
    await this.page.waitForLoadState('networkidle');
  }

  // Common UI interaction helpers
  async fillFormField(label, value) {
    await this.page.fill(`[aria-label="${label}"], [placeholder*="${label}"], input[name*="${label.toLowerCase()}"]`, value);
  }

  async clickButton(buttonText) {
    await this.page.click(`button:has-text("${buttonText}")`);
  }

  async waitForAlert(type = 'success') {
    await this.page.waitForSelector(`[role="alert"]:has-text("${type}"), .MuiAlert-${type}`);
  }

  async waitForApiCall(urlPattern) {
    return this.page.waitForResponse(response =>
      response.url().includes(urlPattern) &&
      response.status() === 200
    );
  }

  // Enhanced features helpers
  async selectAgeVerificationUseCase(useCase) {
    await this.page.click('[role="button"]:has-text("Use Case")');
    await this.page.click(`[role="option"]:has-text("${useCase}")`);
  }

  async verifyQRCodeGenerated() {
    await this.page.waitForSelector('img[alt*="QR"], canvas');
    const qrElement = await this.page.locator('img[alt*="QR"], canvas').first();
    await expect(qrElement).toBeVisible();
  }

  async expandAccordion(title) {
    await this.page.click(`[aria-expanded="false"]:has-text("${title}")`);
  }

  async verifyCardContent(cardTitle, expectedContent) {
    const card = this.page.locator('.MuiCard-root').filter({ hasText: cardTitle });
    await expect(card).toContainText(expectedContent);
  }

  // API response validation helpers
  async mockApiResponse(url, response) {
    await this.page.route(url, route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response)
      });
    });
  }

  async verifyApiCall(urlPattern, expectedPayload = null) {
    const [request] = await Promise.all([
      this.page.waitForRequest(request => request.url().includes(urlPattern)),
      // Trigger action that makes the API call
    ]);

    if (expectedPayload) {
      const payload = request.postDataJSON();
      expect(payload).toMatchObject(expectedPayload);
    }

    return request;
  }

  // Assertion helpers
  async verifySuccessMessage(message) {
    await expect(this.page.locator('.MuiAlert-success')).toContainText(message);
  }

  async verifyErrorMessage(message) {
    await expect(this.page.locator('.MuiAlert-error')).toContainText(message);
  }

  async verifyChipStatus(status, color) {
    const chip = this.page.locator(`.MuiChip-${color}:has-text("${status}")`);
    await expect(chip).toBeVisible();
  }

  async verifyTableRow(rowText) {
    await expect(this.page.locator('tr').filter({ hasText: rowText })).toBeVisible();
  }

  // Screenshot helpers for visual testing
  async takeScreenshot(name) {
    await this.page.screenshot({
      path: `test-results/screenshots/${name}.png`,
      fullPage: true
    });
  }

  async compareScreenshot(name) {
    await expect(this.page).toHaveScreenshot(`${name}.png`);
  }
}

// Mock data for testing
const mockCredentialData = {
  given_name: 'Jane',
  family_name: 'Doe',
  birth_date: '1990-01-01',
  document_number: 'DL123456789',
  issuing_country: 'XX',
  issuing_authority: 'Demo DMV',
  expiry_date: '2030-01-01'
};

const mockVerifiablePresentation = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiablePresentation"],
  "verifiableCredential": [{
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "mDL"],
    "issuer": "did:example:issuer",
    "issuanceDate": new Date().toISOString(),
    "credentialSubject": mockCredentialData
  }]
};

const mockApiResponses = {
  issuerSuccess: {
    success: true,
    credential: {
      id: 'cred_123456',
      type: 'mDL',
      format: 'mso_mdoc',
      created_at: new Date().toISOString()
    }
  },

  verifierSuccess: {
    success: true,
    verified: true,
    checks: [
      { check_name: 'Signature Verification', passed: true, details: 'Valid signature' },
      { check_name: 'Certificate Chain', passed: true, details: 'Valid certificate chain' },
      { check_name: 'Expiry Check', passed: true, details: 'Credential not expired' }
    ],
    presentation_summary: {
      holder: 'Jane Doe',
      credential_type: 'mDL',
      attributes_shared: ['given_name', 'family_name', 'age_over_21']
    }
  },

  ageVerificationSuccess: {
    verification_result: {
      verified: true,
      age_requirement_met: true,
      use_case: 'alcohol_purchase'
    },
    privacy_report: {
      privacy_level: 'high',
      attributes_disclosed: ['age_over_21'],
      attributes_protected: ['birth_date', 'exact_age'],
      zero_knowledge_proof_used: true
    }
  },

  offlineQRSuccess: {
    success: true,
    offline_qr: {
      qr_code_data: 'mock_cbor_data',
      qr_code_image: 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAU...', // Mock base64
      size_bytes: 1024,
      expires_at: new Date(Date.now() + 3600000).toISOString()
    }
  },

  certificateDashboard: {
    overview: {
      total_certificates: 5,
      critical_alerts: 1,
      certificates_needing_renewal: 2,
      expired_certificates: 0
    },
    certificates: [
      {
        certificate_id: 'dsc_001',
        common_name: 'Demo DMV DSC',
        status: 'critical',
        days_until_expiry: 7,
        issuer: 'Demo Root CA'
      },
      {
        certificate_id: 'dsc_002',
        common_name: 'Test Authority DSC',
        status: 'expiring_soon',
        days_until_expiry: 25,
        issuer: 'Test Root CA'
      }
    ]
  },

  policyEvaluation: {
    recommended_action: 'approve',
    disclosed_attributes: ['given_name', 'age_over_21'],
    protected_attributes: ['birth_date', 'address', 'document_number'],
    privacy_score: 0.85,
    rationale: 'Commercial context with verified business, minimal data disclosure approved'
  }
};

module.exports = {
  DemoTestHelpers,
  mockCredentialData,
  mockVerifiablePresentation,
  mockApiResponses
};

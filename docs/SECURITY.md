# Security Policy

## Reporting Security Vulnerabilities

The Marty Platform team takes security seriously. If you discover a security vulnerability, please follow our responsible disclosure process:

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Send details to: <security@marty-platform.com>
3. Include as much information as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested mitigation (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 24 hours
- **Initial Assessment**: We will provide an initial assessment within 72 hours
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 7 days

### Scope

This security policy applies to:

- All Marty Platform services and components
- Associated infrastructure and deployment configurations
- Third-party dependencies and integrations

## Security Measures

### Automated Security Testing

We implement comprehensive automated security testing including:

- **Static Application Security Testing (SAST)**: Code analysis with Bandit, Semgrep, and CodeQL
- **Dynamic Application Security Testing (DAST)**: Runtime vulnerability testing
- **Software Composition Analysis (SCA)**: Dependency vulnerability scanning with Safety and pip-audit
- **Container Security**: Image scanning with Trivy and Docker Scout
- **Secrets Detection**: Automated scanning for exposed credentials with TruffleHog and detect-secrets

### Security Hardening

Our platform implements multiple layers of security:

#### Authentication & Authorization

- Multi-factor authentication (MFA) support
- Role-based access control (RBAC)
- JWT token-based authentication with RS256 signing
- Configurable password policies
- Rate limiting and IP filtering

#### Data Protection

- Encryption at rest and in transit (AES-256-GCM, TLS 1.3)
- Automated key rotation
- Data classification and retention policies
- GDPR compliance features

#### Network Security

- TLS 1.2+ enforcement
- Comprehensive CORS policies
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Network segmentation and access controls

#### Infrastructure Security

- Container security best practices
- Secrets management integration
- Infrastructure as Code (IaC) security scanning
- Kubernetes security policies

### Monitoring & Incident Response

- Real-time security monitoring and alerting
- Centralized logging with ELK stack
- Automated anomaly detection
- 24/7 security monitoring
- Incident response procedures with defined SLAs

### Compliance & Governance

We maintain compliance with industry standards:

- OWASP Top 10 security controls
- NIST Cybersecurity Framework
- ISO 27001 security management
- SOC 2 Type II compliance readiness

## Security Configuration

### Environment-Specific Settings

Security configurations are environment-specific:

- **Development**: Relaxed settings for developer productivity
- **Staging**: Production-like security with testing accommodations  
- **Production**: Maximum security hardening

### Configuration Files

Security settings are managed through:

- `config/security/security_policy.yaml` - Main security policy
- `config/security/bandit.yaml` - Code analysis configuration
- `config/security/automation.yaml` - CI/CD security automation

## Security Best Practices

### For Developers

1. **Secure Coding**:
   - Follow OWASP secure coding guidelines
   - Use parameterized queries to prevent SQL injection
   - Validate and sanitize all inputs
   - Implement proper error handling without information disclosure

2. **Authentication & Session Management**:
   - Never hardcode credentials in source code
   - Use secure session management
   - Implement proper logout functionality
   - Follow principle of least privilege

3. **Data Handling**:
   - Encrypt sensitive data at rest and in transit
   - Implement proper data validation
   - Follow data minimization principles
   - Handle personal data according to privacy regulations

4. **Dependencies**:
   - Keep all dependencies updated
   - Regularly scan for vulnerabilities
   - Use only trusted and well-maintained packages
   - Implement dependency pinning

### For Operations

1. **Infrastructure Security**:
   - Keep all systems updated and patched
   - Implement network segmentation
   - Use security monitoring and logging
   - Regular security assessments

2. **Access Control**:
   - Implement strong authentication mechanisms
   - Use principle of least privilege
   - Regular access reviews and cleanup
   - Monitor for suspicious access patterns

3. **Incident Response**:
   - Maintain updated incident response procedures
   - Regular tabletop exercises
   - Clear escalation procedures
   - Post-incident reviews and improvements

## Security Tools

### Required Tools

- **Bandit**: Python security linter
- **Safety**: Python dependency vulnerability scanner
- **TruffleHog**: Secrets detection
- **Trivy**: Container vulnerability scanner
- **Semgrep**: Static analysis security scanner

### Recommended Tools

- **CodeQL**: Advanced static analysis
- **Docker Scout**: Container security analysis
- **detect-secrets**: Secrets baseline management
- **pip-audit**: Python package vulnerability scanner

## Security Training

All team members are required to complete:

- Secure coding training
- Security awareness training
- Incident response training
- Privacy and compliance training

## Security Metrics

We track and report on:

- Vulnerability discovery and remediation times
- Security scan coverage and results
- Incident response metrics
- Training completion rates
- Compliance audit results

## Contact Information

- **Security Team**: <security@marty-platform.com>
- **Emergency Contact**: <security-emergency@marty-platform.com>
- **Compliance Team**: <compliance@marty-platform.com>

## Legal

This security policy is subject to change. For the most current version, please refer to our GitHub repository. All security reports should follow responsible disclosure practices.

---

**Last Updated**: December 2024  
**Next Review**: March 2025

## Secrets Management

Refer to `docs/SECRETS_MANAGEMENT.md` for the authoritative guidance on handling credentials.

Key points:

- No hard-coded production credentials (searches for `pkiadmin / secret` must not appear outside docs/examples)
- Use environment variable indirection or `_FILE` pattern
- Prefer Docker / Kubernetes secrets in non-prod, Vault or cloud secret managers in prod
- Rotate all secrets regularly; document procedures
- Plan migration to HSM/KMS for cryptographic key operations

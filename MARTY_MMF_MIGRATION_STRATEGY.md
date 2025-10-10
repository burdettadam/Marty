# Marty to Marty Microservices Framework Migration Strategy

## Executive Summary

This document outlines a comprehensive migration strategy to fully integrate Marty with the Marty Microservices Framework (MMF) and eliminate deployment workflow duplication. The migration focuses on three key areas: **Kubernetes deployment patterns**, **Infrastructure as Code standardization**, and **CI/CD pipeline consolidation**.

## Current State Analysis

### Deployment Workflows

**Marty's Current State:**
- Uses Helm charts with templated Kubernetes manifests
- Complex Helm chart structure with 9 template files
- Custom service mesh configuration (Istio/Linkerd)
- Observability integration via ServiceMonitor/PodMonitor
- Support for HPA, PVC, migration jobs, and service accounts

**MMF's Current State:**
- Uses Kustomize with base/overlay pattern
- Simpler structure focused on core microservice components
- Built-in service mesh and observability annotations
- Environment-specific overlays (dev, prod, service-mesh)

### Infrastructure as Code

**Marty's Current State:**
- Comprehensive Terraform modules for AWS, Azure, and GCP
- Modular structure with VPC, EKS, and AWS services modules
- Well-documented with examples

**MMF's Current State:**
- Basic DevOps structure with placeholder infrastructure directory
- No current cloud provisioning scripts

### CI/CD Pipelines

**Marty's Current State:**
- Multiple specialized workflows (CI, CD, security, quality gates)
- Complex container build matrix for 10+ services
- Security scanning with Cosign
- Helm-based deployment process

**MMF's Current State:**
- Basic CI workflow with quality checks
- Simple Python-focused build process
- No deployment automation

## Migration Strategy

### Phase 1: Kubernetes Deployment Migration (4-6 weeks)

#### Step 1.1: Enhance MMF Kustomize Templates (Week 1-2)

**Goal:** Expand MMF's Kustomize base to match Helm chart functionality

**Actions:**
1. **Extend Base Kustomization:**
   ```yaml
   # Add to microservice_project_template/k8s/base/kustomization.yaml
   resources:
     - deployment.yaml
     - service.yaml
     - configmap.yaml
     - serviceaccount.yaml      # NEW
     - servicemonitor.yaml      # NEW
     - podmonitor.yaml         # NEW
     - hpa.yaml                # NEW
   ```

2. **Create Missing Base Resources:**
   - `serviceaccount.yaml` - For RBAC and security contexts
   - `servicemonitor.yaml` - For Prometheus integration
   - `podmonitor.yaml` - For pod-level metrics
   - `hpa.yaml` - For horizontal pod autoscaling

3. **Enhance Base Deployment:**
   - Add security context configurations
   - Include resource limits/requests
   - Add probes (liveness, readiness, startup)
   - Include volume mount points for config

#### Step 1.2: Create Migration-Specific Overlays (Week 2-3)

**Goal:** Create Marty-specific overlays that bridge Helm values to Kustomize patches

**Actions:**
1. **Create Marty Service Overlay:**
   ```
   microservice_project_template/k8s/overlays/marty-services/
   ├── kustomization.yaml
   ├── patch-deployment.yaml
   ├── patch-service.yaml
   ├── migration-job.yaml
   └── pvc.yaml
   ```

2. **Environment-Specific Marty Overlays:**
   ```
   microservice_project_template/k8s/overlays/marty-dev/
   microservice_project_template/k8s/overlays/marty-prod/
   ```

3. **Service-Specific Patches:**
   - Create patches for each Marty service (csca-service, document-signer, etc.)
   - Map Helm values to Kustomize patches

#### Step 1.3: Migration Tools and Documentation (Week 3-4)

**Goal:** Create tools to automate Helm to Kustomize migration

**Actions:**
1. **Helm-to-Kustomize Converter:**
   ```python
   # Add to marty-microservices-framework/scripts/
   helm_to_kustomize_converter.py
   ```
   - Parse existing Helm values.yaml
   - Generate corresponding Kustomize patches
   - Validate output against current deployments

2. **Migration Documentation:**
   ```markdown
   # Add to MMF docs/
   HELM_TO_KUSTOMIZE_MIGRATION.md
   ```
   - Step-by-step migration guide
   - Service-by-service migration checklist
   - Rollback procedures

#### Step 1.4: Pilot Migration (Week 4-5)

**Goal:** Migrate 1-2 Marty services as proof of concept

**Actions:**
1. **Select Pilot Services:**
   - Choose simpler services (e.g., trust-anchor, pkd-service)
   - Services with fewer dependencies

2. **Create Service-Specific Overlays:**
   - Generate Kustomize manifests from Helm templates
   - Test in development environment
   - Validate functionality parity

3. **Deployment Testing:**
   - Deploy using `kubectl apply -k`
   - Compare with Helm-deployed versions
   - Performance and functionality validation

#### Step 1.5: Full Migration (Week 5-6)

**Goal:** Migrate remaining Marty services

**Actions:**
1. **Batch Migration:**
   - Group services by complexity/dependencies
   - Migrate in dependency order

2. **Update CI/CD:**
   - Modify deployment workflows to use Kustomize
   - Remove Helm chart references
   - Update documentation

### Phase 2: Infrastructure as Code Standardization (2-3 weeks)

#### Step 2.1: MMF Infrastructure Enhancement (Week 1)

**Goal:** Add reference infrastructure modules to MMF

**Actions:**
1. **Create MMF Infrastructure Modules:**
   ```
   marty-microservices-framework/devops/infrastructure/
   ├── terraform/
   │   ├── aws/
   │   │   ├── modules/
   │   │   │   ├── eks-cluster/
   │   │   │   ├── networking/
   │   │   │   └── observability/
   │   │   └── examples/
   │   ├── azure/
   │   └── gcp/
   ├── pulumi/
   └── docs/
   ```

2. **Reference Implementation:**
   - Port Marty's proven Terraform modules to MMF
   - Simplify for general use cases
   - Maintain Marty-specific extensions separately

#### Step 2.2: Interface Standardization (Week 2)

**Goal:** Ensure smooth interface between infrastructure and applications

**Actions:**
1. **Terraform Output Standards:**
   ```hcl
   # Standard outputs for MMF compatibility
   output "cluster_endpoint" {
     description = "EKS cluster endpoint"
     value       = module.eks.cluster_endpoint
   }
   
   output "cluster_ca_certificate" {
     description = "EKS cluster certificate authority"
     value       = module.eks.cluster_certificate_authority_data
   }
   ```

2. **Configuration Templates:**
   - Standardize how infrastructure outputs feed into Kustomize
   - Create config map generators for infrastructure values

#### Step 2.3: Marty Infrastructure Migration (Week 2-3)

**Goal:** Migrate Marty to use MMF infrastructure patterns

**Actions:**
1. **Gradual Migration:**
   - Keep Marty's Terraform but align with MMF patterns
   - Use MMF modules where possible
   - Maintain Marty-specific customizations

2. **Documentation:**
   - Document migration path from custom to MMF infrastructure
   - Provide rollback procedures

### Phase 3: CI/CD Pipeline Consolidation (3-4 weeks)

#### Step 3.1: Create Reusable CI/CD Templates (Week 1-2)

**Goal:** Extract common patterns from Marty's workflows into MMF

**Actions:**
1. **Reusable Workflow Templates:**
   ```
   marty-microservices-framework/.github/workflows/
   ├── reusable-ci.yml          # Quality gates, testing
   ├── reusable-build.yml       # Container builds
   ├── reusable-deploy.yml      # Kustomize deployments
   └── reusable-security.yml    # Security scanning
   ```

2. **Template Features:**
   - Matrix builds for multiple services
   - Security scanning with Cosign
   - Multi-environment deployment
   - Quality gates integration

#### Step 3.2: MMF Template Implementation (Week 2-3)

**Goal:** Implement reusable workflows in MMF project template

**Actions:**
1. **Update Project Template:**
   ```yaml
   # microservice_project_template/.github/workflows/ci.yml
   name: CI
   on:
     push:
     pull_request:
   
   jobs:
     quality:
       uses: marty-microservices-framework/.github/workflows/reusable-ci.yml@main
       with:
         python-version: "3.11"
         service-name: ${{ github.repository }}
   ```

2. **Deployment Integration:**
   - Integrate Kustomize deployment into reusable workflows
   - Support for multiple environments
   - Automated rollback capabilities

#### Step 3.3: Marty Workflow Migration (Week 3-4)

**Goal:** Migrate Marty to use MMF reusable workflows

**Actions:**
1. **Workflow Simplification:**
   ```yaml
   # .github/workflows/ci.yml (simplified)
   name: Marty CI
   on:
     push:
     pull_request:
   
   jobs:
     services:
       strategy:
         matrix:
           service: [csca-service, document-signer, dtc-engine, ...]
       uses: marty-microservices-framework/.github/workflows/reusable-ci.yml@main
       with:
         service-name: ${{ matrix.service }}
         dockerfile: docker/${{ matrix.service }}.Dockerfile
   ```

2. **Deployment Automation:**
   - Replace Helm deployments with Kustomize
   - Use MMF deployment templates
   - Maintain environment-specific configurations

## Implementation Timeline

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| **Phase 1: Kubernetes Migration** | 4-6 weeks | Enhanced MMF Kustomize templates, Migration tools, All Marty services migrated |
| **Phase 2: Infrastructure Standardization** | 2-3 weeks | MMF infrastructure modules, Standardized interfaces, Migration documentation |
| **Phase 3: CI/CD Consolidation** | 3-4 weeks | Reusable workflow templates, Simplified Marty workflows, Automated deployments |

**Total Duration:** 9-13 weeks

## Success Criteria

### Kubernetes Deployment Migration
- [ ] All Marty services deployed using Kustomize manifests
- [ ] Functional parity with existing Helm deployments
- [ ] Zero downtime migration process
- [ ] Helm chart directory removed from Marty repository

### Infrastructure Standardization
- [ ] MMF includes reference infrastructure modules
- [ ] Marty infrastructure aligns with MMF patterns
- [ ] Documented migration path for other projects
- [ ] Clear separation between framework and project-specific infrastructure

### CI/CD Consolidation
- [ ] Marty uses MMF reusable workflows
- [ ] 80% reduction in custom CI/CD code in Marty
- [ ] Standardized deployment process across all services
- [ ] Security and quality gates maintained

## Risk Mitigation

### High-Risk Areas
1. **Service Mesh Compatibility:** Different service mesh configurations between Helm and Kustomize
   - **Mitigation:** Thorough testing in staging environments, gradual rollout

2. **Configuration Management:** Complex Helm values may not translate directly to Kustomize
   - **Mitigation:** Create comprehensive mapping documentation, automated validation tools

3. **Deployment Rollback:** Need to maintain ability to rollback to Helm deployments
   - **Mitigation:** Maintain parallel deployment capability during transition period

### Medium-Risk Areas
1. **CI/CD Pipeline Dependencies:** Existing workflows may have hidden dependencies
   - **Mitigation:** Incremental migration, comprehensive testing

2. **Infrastructure Coupling:** Tight coupling between Terraform and Helm
   - **Mitigation:** Interface standardization, gradual decoupling

## Long-term Benefits

### For Marty Project
- **Reduced Maintenance:** Less custom deployment code to maintain
- **Faster Onboarding:** New team members can leverage MMF documentation
- **Consistent Patterns:** Deployment patterns align with framework standards
- **Future-Proof:** Benefit from MMF improvements and community contributions

### For MMF Ecosystem
- **Real-world Validation:** Marty serves as comprehensive validation of MMF patterns
- **Enhanced Features:** Infrastructure and CI/CD templates benefit all MMF users
- **Community Examples:** Marty migration serves as reference for other projects
- **Framework Maturity:** Handling complex migration scenarios improves framework robustness

## Next Steps

1. **Stakeholder Approval:** Get approval for migration strategy and timeline
2. **Team Assignment:** Assign dedicated team members for each phase
3. **Environment Setup:** Prepare staging environments for testing
4. **Phase 1 Kickoff:** Begin with MMF Kustomize template enhancement
5. **Communication Plan:** Regular progress updates and stakeholder communication

---

*This migration strategy provides a comprehensive roadmap for eliminating duplication between Marty and MMF while ensuring zero-downtime migration and maintaining all existing functionality.*
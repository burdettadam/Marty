# Marty Platform - AWS Infrastructure

This directory contains Terraform modules for deploying the Marty microservices platform on AWS.

## Architecture Overview

The infrastructure consists of:
- **VPC Module**: Creates a secure VPC with public/private subnets, NAT gateways, and routing
- **EKS Module**: Provisions an Amazon EKS cluster with managed node groups
- **Services Module**: Deploys supporting AWS services (RDS PostgreSQL, MSK Kafka, ElastiCache Redis, ECR)

## Directory Structure

```
terraform/aws/
├── modules/           # Reusable Terraform modules
│   ├── vpc/          # VPC networking infrastructure
│   ├── eks/          # EKS cluster and node groups
│   └── services/     # AWS managed services
├── examples/         # Example deployments
│   └── complete/     # Full infrastructure example
└── README.md         # This file
```

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate permissions
- kubectl (for EKS cluster access)

## Quick Start

1. **Clone and navigate to the example:**
   ```bash
   cd terraform/aws/examples/complete
   ```

2. **Initialize Terraform:**
   ```bash
   terraform init
   ```

3. **Review the plan:**
   ```bash
   terraform plan
   ```

4. **Apply the infrastructure:**
   ```bash
   terraform apply
   ```

## Modules

### VPC Module (`modules/vpc/`)

Creates a VPC with:
- Public and private subnets across multiple availability zones
- Internet Gateway for public subnets
- NAT Gateways for private subnet internet access
- Route tables and associations

**Inputs:**
- `vpc_cidr_block`: CIDR block for the VPC
- `availability_zones`: List of AZs to use
- `public_subnet_cidrs`: CIDR blocks for public subnets
- `private_subnet_cidrs`: CIDR blocks for private subnets

**Outputs:**
- `vpc_id`: VPC ID
- `public_subnet_ids`: List of public subnet IDs
- `private_subnet_ids`: List of private subnet IDs

### EKS Module (`modules/eks/`)

Creates an EKS cluster with:
- Managed Kubernetes control plane
- IAM roles for cluster and nodes
- Configurable node groups

**Inputs:**
- `cluster_name`: Name of the EKS cluster
- `vpc_id`: VPC ID where cluster will be created
- `subnet_ids`: Subnet IDs for cluster
- `kubernetes_version`: K8s version (default: 1.28)
- `node_groups`: Map of node group configurations

**Outputs:**
- `cluster_name`: EKS cluster name
- `cluster_endpoint`: API server endpoint
- `cluster_certificate_authority_data`: CA data for kubectl

### Services Module (`modules/services/`)

Deploys AWS managed services:
- **RDS PostgreSQL**: Database for application data
- **MSK Kafka**: Event streaming platform
- **ElastiCache Redis**: Caching layer
- **ECR Repositories**: Container image registries

**Inputs:**
- `vpc_id`: VPC ID
- `subnet_ids`: Subnet IDs for services

**Outputs:**
- Database connection details
- Kafka bootstrap brokers
- Redis endpoint
- ECR repository URLs

## Security Considerations

- All services are deployed in private subnets
- Security groups restrict access to VPC CIDR ranges
- Database passwords should be managed via AWS Secrets Manager
- Enable encryption at rest for all services in production

## Cost Optimization

- Use appropriate instance sizes for your workload
- Configure auto-scaling for EKS node groups
- Enable spot instances for non-critical workloads
- Set up cost allocation tags

## Next Steps

After deploying infrastructure:
1. Configure kubectl to access the EKS cluster
2. Deploy Marty services using Helm charts
3. Set up monitoring with Prometheus/Grafana
4. Configure CI/CD pipelines for automated deployments

## Troubleshooting

- **EKS cluster creation fails**: Ensure IAM permissions include EKS policies
- **Node groups won't join cluster**: Check security group rules and subnet configurations
- **Services can't connect to database**: Verify VPC peering and security group rules

For detailed documentation, see the main project README.
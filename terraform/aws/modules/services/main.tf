terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpc_id" {
  description = "VPC ID where resources will be created"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for resources"
  type        = list(string)
}

variable "security_group_ids" {
  description = "List of security group IDs"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# PostgreSQL RDS Instance
resource "aws_db_subnet_group" "postgresql" {
  name       = "marty-postgresql-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(
    var.tags,
    {
      Name = "marty-postgresql-subnet-group"
    }
  )
}

resource "aws_security_group" "postgresql" {
  name_prefix = "marty-postgresql-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = merge(
    var.tags,
    {
      Name = "marty-postgresql-sg"
    }
  )
}

resource "aws_db_instance" "postgresql" {
  identifier             = "marty-postgresql"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_type           = "gp2"
  db_name                = "marty"
  username               = "marty_admin"
  password               = "CHANGE_ME_IN_PRODUCTION"  # Use AWS Secrets Manager in production
  db_subnet_group_name   = aws_db_subnet_group.postgresql.name
  vpc_security_group_ids = [aws_security_group.postgresql.id]
  skip_final_snapshot    = true

  tags = merge(
    var.tags,
    {
      Name = "marty-postgresql"
    }
  )
}

# MSK Kafka Cluster
resource "aws_security_group" "kafka" {
  name_prefix = "marty-kafka-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 9094
    to_port     = 9094
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = merge(
    var.tags,
    {
      Name = "marty-kafka-sg"
    }
  )
}

resource "aws_msk_cluster" "kafka" {
  cluster_name           = "marty-kafka"
  kafka_version          = "3.4.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.kafka.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "marty-kafka"
    }
  )
}

# ElastiCache Redis Cluster
resource "aws_security_group" "redis" {
  name_prefix = "marty-redis-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = merge(
    var.tags,
    {
      Name = "marty-redis-sg"
    }
  )
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "marty-redis-subnet-group"
  subnet_ids = var.subnet_ids
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "marty-redis"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.redis.name
  security_group_ids   = [aws_security_group.redis.id]

  tags = merge(
    var.tags,
    {
      Name = "marty-redis"
    }
  )
}

# ECR Repositories
resource "aws_ecr_repository" "services" {
  for_each = toset([
    "csca-service",
    "document-signer",
    "dtc-engine",
    "inspection-system",
    "mdl-engine",
    "mdoc-engine",
    "passport-engine",
    "pkd-service",
    "trust-anchor",
    "ui-app"
  ])

  name                 = "marty/${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(
    var.tags,
    {
      Name = "marty-${each.key}"
    }
  )
}

output "postgresql_endpoint" {
  description = "PostgreSQL RDS endpoint"
  value       = aws_db_instance.postgresql.endpoint
}

output "postgresql_port" {
  description = "PostgreSQL RDS port"
  value       = aws_db_instance.postgresql.port
}

output "kafka_bootstrap_brokers" {
  description = "MSK Kafka bootstrap brokers"
  value       = aws_msk_cluster.kafka.bootstrap_brokers_tls
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
}

output "redis_port" {
  description = "Redis cluster port"
  value       = aws_elasticache_cluster.redis.port
}

output "ecr_repository_urls" {
  description = "ECR repository URLs"
  value = {
    for repo in aws_ecr_repository.services :
    repo.name => repo.repository_url
  }
}

# Terraform Module OPA Policy Examples

This directory contains example [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) policies for use with Nuon's policy enforcement system for Terraform module components.

## Overview

Nuon supports policy evaluation during the planning phase of Terraform module deployments. These policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), OPA's policy language, and can enforce security, compliance, cost management, and operational best practices.

## How Policies Work

1. **Trigger**: Policies are evaluated after the Terraform plan is generated, before deployment
2. **Input**: Each policy receives the Terraform plan in JSON format (terraform-json standard)
3. **Rules**: Policies define `deny` rules (block deployment) and `warn` rules (log warnings)
4. **Enforcement**: If any `deny` rules match, the deployment is blocked

### Input Format

All policies receive input in this format:

```json
{
  "plan": {
    "format_version": "1.1",
    "terraform_version": "1.5.0",
    "resource_changes": [
      {
        "address": "aws_instance.example",
        "type": "aws_instance",
        "change": {
          "actions": ["create"],
          "before": null,
          "after": {
            "instance_type": "t3.micro",
            "tags": {...}
          }
        }
      }
    ]
  }
}
```

## Example Policies

### 1. Security Group Ingress (`security-group-ingress.rego`)

**Purpose**: Prevent creation of security groups that allow unrestricted internet access on sensitive ports.

**What it checks**:
- ⛔ **Denies**: Ingress rules allowing 0.0.0.0/0 on ports like SSH (22), PostgreSQL (5432), MySQL (3306), etc.
- ⚠️ **Warns**: Ingress rules allowing 0.0.0.0/0 on any port, security groups without descriptions

**Use cases**:
- Prevent accidental database exposure
- Enforce security best practices
- Comply with security frameworks (CIS, SOC2)

**Example violation**:
```hcl
resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ⛔ DENIED
  }
}
```

**Example fix**:
```hcl
resource "aws_security_group" "db" {
  description = "PostgreSQL database security group"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # ✅ ALLOWED - specific CIDR
  }
}
```

---

### 2. Encryption at Rest (`encryption-at-rest.rego`)

**Purpose**: Ensure all data storage resources are encrypted at rest.

**What it checks**:
- ⛔ **Denies**:
  - RDS instances/clusters without `storage_encrypted = true`
  - EBS volumes without `encrypted = true`
  - EFS file systems without `encrypted = true`
  - Secrets Manager secrets without customer-managed KMS keys
- ⚠️ **Warns**:
  - S3 buckets without encryption configuration
  - Kinesis streams, SNS topics, SQS queues without KMS encryption
  - ElastiCache without encryption in transit/at rest

**Use cases**:
- Comply with HIPAA, PCI-DSS, SOC2
- Protect sensitive data
- Meet organizational security standards

**Example violation**:
```hcl
resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
  # Missing: storage_encrypted = true  ⛔ DENIED
}
```

**Example fix**:
```hcl
resource "aws_db_instance" "main" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = true  # ✅ ALLOWED
  kms_key_id        = aws_kms_key.rds.arn  # Optional: use custom KMS key
}
```

---

### 3. Required Tags (`required-tags.rego`)

**Purpose**: Enforce consistent resource tagging across all infrastructure.

**What it checks**:
- ⛔ **Denies**: Resources missing required tags (`Environment`, `Owner`, `CostCenter`)
- ⚠️ **Warns**:
  - Tags with empty values
  - Non-standard Environment values
  - Missing recommended tags
  - Tags not following PascalCase convention

**Use cases**:
- Enable cost allocation and chargeback
- Track resource ownership
- Support compliance and audit requirements
- Improve resource management

**Example violation**:
```hcl
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  # Missing required tags ⛔ DENIED
}
```

**Example fix**:
```hcl
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  tags = {
    Environment  = "production"
    Owner        = "platform-team@example.com"
    CostCenter   = "engineering"
    Application  = "web-frontend"  # Recommended
    ManagedBy    = "Terraform"     # Recommended
  }
}
```

---

### 4. Destructive Changes (`destructive-changes.rego`)

**Purpose**: Prevent accidental data loss and service disruption from destructive operations.

**What it checks**:
- ⛔ **Denies**:
  - Deletion of critical resources (databases, S3 buckets, KMS keys)
  - Disabling RDS backup retention
  - Deletion of versioned S3 buckets
- ⚠️ **Warns**:
  - Any resource deletion
  - Resource replacements causing downtime
  - Security group rule removals
  - VPC deletions

**Use cases**:
- Prevent accidental data loss
- Protect production resources
- Require manual review for destructive operations
- Enforce data retention policies

**Example denial**:
```hcl
# In Terraform plan: deleting a database
resource "aws_db_instance" "main" {
  # ... configuration ...
}
# Terraform action: DELETE ⛔ DENIED
```

**Best practice**:
```hcl
# Use lifecycle rules to prevent accidental deletion
resource "aws_db_instance" "main" {
  # ... configuration ...

  lifecycle {
    prevent_destroy = true
  }
}
```

---

### 5. Cost Management (`cost-management.rego`)

**Purpose**: Control cloud spending by preventing expensive resource configurations.

**What it checks**:
- ⛔ **Denies**:
  - EC2 instances larger than 16xlarge or GPU instances
  - RDS instances larger than 16xlarge
  - Provisioned IOPS > 10,000 without justification
  - Multi-AZ RDS in development environments
  - Load Balancers in development environments
- ⚠️ **Warns**:
  - Large instance types (2xlarge, 4xlarge, 8xlarge)
  - RDS storage > 1TB
  - Multiple NAT Gateways
  - DynamoDB provisioned capacity mode

**Use cases**:
- Prevent cost overruns
- Enforce budget constraints
- Optimize resource sizing
- Control non-production spending

**Example violation**:
```hcl
resource "aws_instance" "web" {
  instance_type = "m5.24xlarge"  # ⛔ DENIED - too expensive
}
```

**Example fix**:
```hcl
# Use smaller instances with auto-scaling
resource "aws_instance" "web" {
  instance_type = "m5.xlarge"  # ✅ ALLOWED
}

# Or use Auto Scaling Group for cost optimization
resource "aws_autoscaling_group" "web" {
  min_size = 2
  max_size = 10

  launch_template {
    id = aws_launch_template.web.id
  }
}
```

---

### 6. IAM Security (`iam-security.rego`)

**Purpose**: Enforce IAM best practices and prevent privilege escalation.

**What it checks**:
- ⛔ **Denies**:
  - IAM policies with wildcard permissions (`Action: "*", Resource: "*"`)
  - Administrative permissions without justification
  - Dangerous IAM actions on all resources
  - Privilege escalation paths (PassRole + service creation)
  - S3 bucket policies allowing public access
  - IAM roles with wildcard principals in trust policies
- ⚠️ **Warns**:
  - Policies without conditions on broad permissions
  - IAM users with inline policies
  - Cross-account access without ExternalId

**Use cases**:
- Enforce principle of least privilege
- Prevent privilege escalation
- Comply with security frameworks
- Protect against unauthorized access

**Example violation**:
```hcl
resource "aws_iam_policy" "bad" {
  name = "admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"       # ⛔ DENIED - wildcard action
      Resource = "*"       # ⛔ DENIED - wildcard resource
    }]
  })
}
```

**Example fix**:
```hcl
resource "aws_iam_policy" "good" {
  name = "s3-read-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }]
  })
}
```

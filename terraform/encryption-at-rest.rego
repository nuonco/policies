# Encryption at Rest Policy
#
# This policy enforces encryption at rest for various AWS resources including
# RDS databases, S3 buckets, EBS volumes, and other storage services.
#
# Use Case:
# - Ensure compliance with security standards (SOC2, HIPAA, PCI-DSS)
# - Prevent accidental storage of sensitive data without encryption
# - Enforce organizational security policies
#
# Policy Type: terraform_module
# Engine: opa
#
# Example violation:
# ```hcl
# resource "aws_db_instance" "main" {
#   engine         = "postgres"
#   instance_class = "db.t3.micro"
#   # Missing: storage_encrypted = true  ⛔ This will be denied
# }
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny RDS instances without encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes

    # Check for RDS instances
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Encryption is not enabled or explicitly disabled
    not resource.storage_encrypted

    msg := sprintf(
        "RDS instance '%s' does not have storage encryption enabled. Set storage_encrypted = true.",
        [resource_change.address]
    )
}

# Deny RDS clusters without encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_rds_cluster"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.storage_encrypted

    msg := sprintf(
        "RDS cluster '%s' does not have storage encryption enabled. Set storage_encrypted = true.",
        [resource_change.address]
    )
}

# Deny S3 buckets without default encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_s3_bucket"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Check if bucket versioning or other critical configs exist
    # S3 encryption is now configured via aws_s3_bucket_server_side_encryption_configuration
    # This check ensures the bucket itself doesn't have legacy encryption settings disabled

    # Note: In Terraform AWS provider v4+, encryption is configured separately
    # This rule serves as a reminder to configure encryption
    not resource.server_side_encryption_configuration

    msg := sprintf(
        "S3 bucket '%s' should have server-side encryption configured. Use aws_s3_bucket_server_side_encryption_configuration resource.",
        [resource_change.address]
    )
}

# Deny S3 bucket encryption configurations without encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Check that encryption is actually configured
    not resource.rule

    msg := sprintf(
        "S3 bucket encryption configuration '%s' has no encryption rules defined.",
        [resource_change.address]
    )
}

# Deny EBS volumes without encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_ebs_volume"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.encrypted

    msg := sprintf(
        "EBS volume '%s' is not encrypted. Set encrypted = true.",
        [resource_change.address]
    )
}

# Deny EFS file systems without encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_efs_file_system"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.encrypted

    msg := sprintf(
        "EFS file system '%s' is not encrypted. Set encrypted = true.",
        [resource_change.address]
    )
}

# Deny DynamoDB tables without encryption (if encryption is explicitly disabled)
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_dynamodb_table"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Check if server_side_encryption is explicitly set but disabled
    resource.server_side_encryption
    not resource.server_side_encryption.enabled

    msg := sprintf(
        "DynamoDB table '%s' has server-side encryption explicitly disabled. Enable encryption for compliance.",
        [resource_change.address]
    )
}

# Warn about Redshift clusters without encryption
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_redshift_cluster"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.encrypted

    msg := sprintf(
        "Warning: Redshift cluster '%s' is not encrypted. Consider enabling encryption for sensitive data.",
        [resource_change.address]
    )
}

# Warn about Kinesis streams without encryption
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_kinesis_stream"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Check if encryption is not configured
    not resource.encryption_type

    msg := sprintf(
        "Warning: Kinesis stream '%s' does not have encryption configured. Consider using KMS encryption.",
        [resource_change.address]
    )
}

# Warn about SNS topics without encryption
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_sns_topic"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.kms_master_key_id

    msg := sprintf(
        "Warning: SNS topic '%s' does not have KMS encryption. Consider adding kms_master_key_id for sensitive data.",
        [resource_change.address]
    )
}

# Warn about SQS queues without encryption
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_sqs_queue"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.kms_master_key_id

    msg := sprintf(
        "Warning: SQS queue '%s' does not have KMS encryption. Consider adding kms_master_key_id for sensitive data.",
        [resource_change.address]
    )
}

# Deny Secrets Manager secrets without KMS encryption
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_secretsmanager_secret"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Secrets Manager uses default AWS managed key if kms_key_id is not specified
    # We require a customer-managed KMS key for better control
    not resource.kms_key_id

    msg := sprintf(
        "Secrets Manager secret '%s' should use a customer-managed KMS key. Set kms_key_id.",
        [resource_change.address]
    )
}

# Warn about ElastiCache clusters without encryption in transit
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_elasticache_replication_group", "aws_elasticache_cluster"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.transit_encryption_enabled

    msg := sprintf(
        "Warning: ElastiCache resource '%s' does not have transit encryption enabled. Consider enabling for sensitive data.",
        [resource_change.address]
    )
}

# Warn about ElastiCache clusters without encryption at rest
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_elasticache_replication_group"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    not resource.at_rest_encryption_enabled

    msg := sprintf(
        "Warning: ElastiCache replication group '%s' does not have at-rest encryption enabled. Consider enabling for sensitive data.",
        [resource_change.address]
    )
}

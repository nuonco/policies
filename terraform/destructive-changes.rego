# Destructive Changes Policy
#
# This policy warns about or prevents destructive operations that could
# result in data loss or service disruption.
#
# Use Case:
# - Prevent accidental deletion of critical resources
# - Warn about replace operations that cause downtime
# - Protect production data from destructive changes
# - Require extra review for high-risk operations
#
# Policy Type: terraform_module
# Engine: opa
#
# Example warning:
# ```hcl
# resource "aws_db_instance" "main" {
#   instance_class = "db.t3.large"  # Changing this triggers replacement
#   # ⚠️ This will trigger a warning about resource replacement
# }
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Define critical resources that should never be deleted
critical_resources := {
    "aws_db_instance",           # RDS databases
    "aws_rds_cluster",            # RDS clusters
    "aws_dynamodb_table",         # DynamoDB tables
    "aws_s3_bucket",              # S3 buckets
    "aws_efs_file_system",        # EFS file systems
    "aws_secretsmanager_secret",  # Secrets Manager secrets
    "aws_kms_key",                # KMS encryption keys
}

# Define resources where replacement causes significant downtime
downtime_on_replace := {
    "aws_instance",
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_ecs_service",
    "aws_lb",
}

# Deny deletion of critical resources
deny contains msg if {
    some resource_change in input.plan.resource_changes

    # Check if resource type is critical
    resource_change.type in critical_resources

    # Check if the action is delete
    resource_change.change.actions[_] == "delete"

    msg := sprintf(
        "Deletion of critical resource '%s' (type: %s) is not allowed. This could result in data loss. If deletion is intentional, remove this policy or exclude this component.",
        [resource_change.address, resource_change.type]
    )
}

# Warn about replacement of critical resources
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in critical_resources

    # Check for replace action (delete + create in same plan)
    actions := resource_change.change.actions
    count(actions) == 2
    actions[0] == "delete"
    actions[1] == "create"

    msg := sprintf(
        "Warning: Critical resource '%s' (type: %s) will be replaced. This may cause data loss or service disruption. Review carefully before approving.",
        [resource_change.address, resource_change.type]
    )
}

# Warn about resources that will be replaced and cause downtime
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in downtime_on_replace

    # Check for replace action
    actions := resource_change.change.actions
    count(actions) == 2
    actions[0] == "delete"
    actions[1] == "create"

    msg := sprintf(
        "Warning: Resource '%s' (type: %s) will be replaced. This will cause service downtime. Consider using blue-green deployment if available.",
        [resource_change.address, resource_change.type]
    )
}

# Warn about any resource deletion
warn contains msg if {
    some resource_change in input.plan.resource_changes

    # Any deletion that's not a critical resource (those are denied)
    resource_change.change.actions[_] == "delete"
    not resource_change.type in critical_resources

    msg := sprintf(
        "Warning: Resource '%s' (type: %s) will be deleted. Ensure this is intentional.",
        [resource_change.address, resource_change.type]
    )
}

# Deny deletion of S3 buckets with versioning enabled
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_s3_bucket"
    resource_change.change.actions[_] == "delete"

    # Check if the bucket had versioning enabled before deletion
    before := resource_change.change.before
    before.versioning[_].enabled == true

    msg := sprintf(
        "Deletion of versioned S3 bucket '%s' is not allowed. Versioned buckets may contain important historical data. Disable this policy or exclude this component if deletion is required.",
        [resource_change.address]
    )
}

# Warn about RDS instance storage downsizing
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] == "update"

    before := resource_change.change.before
    after := resource_change.change.after

    # Check if allocated storage is being reduced
    before.allocated_storage > after.allocated_storage

    msg := sprintf(
        "Warning: RDS instance '%s' storage is being reduced from %d GB to %d GB. AWS does not support reducing storage size - this will force replacement and potential data loss.",
        [resource_change.address, before.allocated_storage, after.allocated_storage]
    )
}

# Warn about security group rule deletions
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_security_group"
    resource_change.change.actions[_] == "update"

    before := resource_change.change.before
    after := resource_change.change.after

    # Count ingress rules
    before_ingress_count := count(before.ingress)
    after_ingress_count := count(after.ingress)

    # Rules are being removed
    before_ingress_count > after_ingress_count

    msg := sprintf(
        "Warning: Security group '%s' will have ingress rules removed (%d -> %d rules). This may break application connectivity.",
        [resource_change.address, before_ingress_count, after_ingress_count]
    )
}

# Deny deletion of KMS keys (they have a mandatory waiting period)
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_kms_key"
    resource_change.change.actions[_] == "delete"

    before := resource_change.change.before

    # Only deny if deletion_window_in_days is not set or is less than 30 days
    not before.deletion_window_in_days

    msg := sprintf(
        "KMS key '%s' deletion requires a deletion_window_in_days >= 7. Set this parameter explicitly to confirm intentional deletion.",
        [resource_change.address]
    )
}

# Warn about VPC deletion
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_vpc"
    resource_change.change.actions[_] == "delete"

    msg := sprintf(
        "Warning: VPC '%s' will be deleted. This will delete all associated subnets, route tables, and network resources. Ensure dependent resources are handled.",
        [resource_change.address]
    )
}

# Warn about DynamoDB table deletion or replacement
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_dynamodb_table"

    # Delete or replace
    resource_change.change.actions[_] == "delete"

    msg := sprintf(
        "Warning: DynamoDB table '%s' will be deleted or replaced. This will result in permanent data loss. Ensure you have a backup or this is intentional.",
        [resource_change.address]
    )
}

# Deny changes that remove backup retention
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] == "update"

    before := resource_change.change.before
    after := resource_change.change.after

    # Backup retention is being reduced to 0 (disabled)
    before.backup_retention_period > 0
    after.backup_retention_period == 0

    msg := sprintf(
        "RDS instance '%s' backup retention is being disabled. This violates data protection policies. Maintain backup_retention_period >= 7.",
        [resource_change.address]
    )
}

# Warn about Lambda function deletion
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_lambda_function"
    resource_change.change.actions[_] == "delete"

    msg := sprintf(
        "Warning: Lambda function '%s' will be deleted. Ensure no services depend on this function.",
        [resource_change.address]
    )
}

# Warn about IAM role deletion
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_iam_role"
    resource_change.change.actions[_] == "delete"

    msg := sprintf(
        "Warning: IAM role '%s' will be deleted. Ensure no resources or services are using this role.",
        [resource_change.address]
    )
}

# Deny deletion of CloudWatch Log Groups with retention
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_cloudwatch_log_group"
    resource_change.change.actions[_] == "delete"

    before := resource_change.change.before

    # If retention is set, logs are being kept for compliance
    before.retention_in_days > 0

    msg := sprintf(
        "CloudWatch Log Group '%s' has retention policy (%d days) and cannot be deleted. This may violate compliance requirements. Archive logs first if deletion is required.",
        [resource_change.address, before.retention_in_days]
    )
}

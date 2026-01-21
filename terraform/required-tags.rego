# Required Tags Policy
#
# This policy enforces tagging standards across AWS resources to ensure
# proper cost allocation, ownership tracking, and resource management.
#
# Use Case:
# - Enforce organizational tagging standards
# - Enable cost allocation and chargeback
# - Track resource ownership and lifecycle
# - Support compliance and audit requirements
#
# Policy Type: terraform_module
# Engine: opa
#
# Example violation:
# ```hcl
# resource "aws_instance" "web" {
#   ami           = "ami-12345678"
#   instance_type = "t3.micro"
#   # Missing required tags ⛔ This will be denied
# }
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Define required tags for all resources
required_tags := {
    "Environment",   # e.g., production, staging, development
    "Owner",        # e.g., team name or email
    "CostCenter",   # e.g., department or project code
}

# Define resources that must be tagged
# This list includes common AWS resources that support tagging
taggable_resources := {
    "aws_instance",
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "aws_ebs_volume",
    "aws_efs_file_system",
    "aws_vpc",
    "aws_subnet",
    "aws_security_group",
    "aws_lb",
    "aws_lb_target_group",
    "aws_ecs_cluster",
    "aws_ecs_service",
    "aws_eks_cluster",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_lambda_function",
    "aws_dynamodb_table",
    "aws_kinesis_stream",
    "aws_sns_topic",
    "aws_sqs_queue",
    "aws_cloudwatch_log_group",
    "aws_kms_key",
    "aws_secretsmanager_secret",
    "aws_ecr_repository",
}

# Helper function to get tags from a resource
get_tags(resource) := tags if {
    tags := resource.tags
} else := {} if {
    # Return empty object if tags don't exist
    true
}

# Helper function to check if all required tags are present
missing_required_tags(tags) := missing if {
    present_tags := {tag | tags[tag]}
    missing := required_tags - present_tags
}

# Deny resources that are missing required tags
deny contains msg if {
    some resource_change in input.plan.resource_changes

    # Only check taggable resources
    resource_change.type in taggable_resources

    # Only check creates and updates
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Get missing tags
    missing := missing_required_tags(tags)
    count(missing) > 0

    msg := sprintf(
        "Resource '%s' is missing required tags: %v. All resources must have: %v",
        [resource_change.address, missing, required_tags]
    )
}

# Warn about resources with empty tag values
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Check each required tag
    some required_tag in required_tags

    # Tag exists but is empty or just whitespace
    tag_value := tags[required_tag]
    trimmed_value := trim_space(tag_value)
    trimmed_value == ""

    msg := sprintf(
        "Warning: Resource '%s' has an empty value for required tag '%s'. Provide a meaningful value.",
        [resource_change.address, required_tag]
    )
}

# Warn about non-standard tag formats for Environment
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Check if Environment tag exists and has a valid value
    env_value := tags["Environment"]
    not env_value in {"production", "staging", "development", "test", "demo"}

    msg := sprintf(
        "Warning: Resource '%s' has non-standard Environment tag value '%s'. Use: production, staging, development, test, or demo.",
        [resource_change.address, env_value]
    )
}

# Warn about resources missing recommended optional tags
recommended_tags := {
    "Application",  # Application name
    "ManagedBy",   # e.g., Terraform, Nuon
    "Compliance",  # e.g., HIPAA, PCI-DSS, SOC2
}

warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Check for missing recommended tags
    present_tags := {tag | tags[tag]}
    missing := recommended_tags - present_tags
    count(missing) > 0

    msg := sprintf(
        "Warning: Resource '%s' is missing recommended tags: %v. Consider adding for better resource management.",
        [resource_change.address, missing]
    )
}

# Deny resources with invalid characters in tag values
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Check each tag value
    some tag_key, tag_value in tags

    # Check for potentially problematic characters
    # AWS tag values can contain most characters, but some are problematic in automation
    contains(tag_value, "\n")  # Newlines cause issues

    msg := sprintf(
        "Resource '%s' has invalid characters in tag '%s'. Tag values should not contain newlines.",
        [resource_change.address, tag_key]
    )
}

# Warn about tag key naming conventions
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Check each tag key
    some tag_key, _ in tags

    # Tag keys should use PascalCase (start with capital letter)
    # This is a common convention for AWS tags
    first_char := substring(tag_key, 0, 1)
    lower_first := lower(first_char)
    first_char == lower_first

    # Don't warn about aws: prefixed tags (AWS managed)
    not startswith(tag_key, "aws:")

    msg := sprintf(
        "Warning: Resource '%s' has tag '%s' that doesn't follow PascalCase convention. Consider renaming to start with a capital letter.",
        [resource_change.address, tag_key]
    )
}

# Deny tags with reserved prefixes
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    # Check each tag key
    some tag_key, _ in tags

    # Don't allow custom tags with aws: prefix (reserved by AWS)
    startswith(tag_key, "aws:")

    msg := sprintf(
        "Resource '%s' has tag '%s' with reserved 'aws:' prefix. This prefix is reserved for AWS-managed tags.",
        [resource_change.address, tag_key]
    )
}

# Helper: Validate email format for Owner tag
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in taggable_resources
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    tags := get_tags(resource)

    owner_value := tags["Owner"]

    # Simple email validation: should contain @ symbol
    # For more complex validation, you could use regex module
    not contains(owner_value, "@")

    msg := sprintf(
        "Warning: Resource '%s' has Owner tag '%s' that doesn't appear to be an email address. Use a valid email for accountability.",
        [resource_change.address, owner_value]
    )
}

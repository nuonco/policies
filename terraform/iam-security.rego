# IAM Security Policy
#
# This policy enforces IAM best practices and prevents the creation of
# overly permissive IAM policies that could lead to security vulnerabilities.
#
# Use Case:
# - Prevent privilege escalation vulnerabilities
# - Enforce principle of least privilege
# - Comply with security frameworks (CIS, SOC2, etc.)
# - Prevent accidental exposure of AWS resources
#
# Policy Type: terraform_module
# Engine: opa
#
# Example violation:
# ```hcl
# resource "aws_iam_policy" "bad" {
#   policy = jsonencode({
#     Statement = [{
#       Effect   = "Allow"
#       Action   = "*"          # ⛔ Wildcard actions denied
#       Resource = "*"          # ⛔ Wildcard resources denied
#     }]
#   })
# }
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Dangerous IAM actions that should rarely be allowed
dangerous_iam_actions := {
    "iam:*",
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:CreatePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
}

# Administrative actions that grant full control
admin_actions := {
    "*:*",
    "iam:*",
    "s3:*",
    "ec2:*",
    "rds:*",
}

# Helper: Parse IAM policy document from JSON string
parse_policy_document(policy_json) := policy if {
    policy := json.unmarshal(policy_json)
}

# Helper: Get all statements from a policy document
get_statements(policy_doc) := statements if {
    statements := policy_doc.Statement
} else := [] if {
    # If Statement is not present, return empty array
    true
}

# Helper: Check if an action matches a pattern (supports wildcards)
action_matches(action, pattern) if {
    action == pattern
}

action_matches(action, pattern) if {
    # Pattern contains wildcard
    contains(pattern, "*")

    # Split on wildcard
    parts := split(pattern, "*")

    # Check if action starts with prefix (for patterns like "s3:*")
    count(parts) == 2
    parts[1] == ""
    startswith(action, parts[0])
}

action_matches(action, pattern) if {
    # Full wildcard
    pattern == "*"
}

# Deny IAM policies with full wildcard permissions
deny contains msg if {
    some resource_change in input.plan.resource_changes

    # Check IAM policy resources
    resource_change.type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Parse the policy document
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    # Check each statement
    some statement in statements

    # Statement allows actions
    statement.Effect == "Allow"

    # Check if actions include wildcards
    some action in statement.Action
    action == "*"

    # Check if resources include wildcards
    some resource_arn in statement.Resource
    resource_arn == "*"

    msg := sprintf(
        "IAM policy '%s' grants wildcard permissions (Action: '*', Resource: '*'). This violates principle of least privilege. Specify explicit actions and resources.",
        [resource_change.address]
    )
}

# Deny IAM policies with dangerous actions on all resources
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Check for dangerous IAM actions
    some action in statement.Action
    some dangerous in dangerous_iam_actions
    action_matches(action, dangerous)

    # On all resources
    some resource_arn in statement.Resource
    resource_arn == "*"

    msg := sprintf(
        "IAM policy '%s' grants dangerous action '%s' on all resources (*). This could enable privilege escalation. Restrict to specific resources.",
        [resource_change.address, action]
    )
}

# Deny IAM policies with administrative permissions
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Check for admin-level actions
    some action in statement.Action
    some admin_action in admin_actions
    action_matches(action, admin_action)

    msg := sprintf(
        "IAM policy '%s' grants administrative permissions ('%s'). Use AWS managed policies like AdministratorAccess or create specific policies for actual needs.",
        [resource_change.address, action]
    )
}

# Deny IAM roles with missing assume role policy trust relationships
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_iam_role"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Parse assume role policy
    assume_policy := parse_policy_document(resource.assume_role_policy)
    statements := get_statements(assume_policy)

    # Check for overly permissive trust relationships
    some statement in statements
    statement.Effect == "Allow"

    # Check for wildcard principals
    principal := statement.Principal
    some service in principal.AWS
    service == "*"

    msg := sprintf(
        "IAM role '%s' has overly permissive assume role policy with wildcard principal ('*'). Specify explicit AWS accounts or services that can assume this role.",
        [resource_change.address]
    )
}

# Warn about IAM policies without conditions
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Statement has broad permissions but no conditions
    some action in statement.Action
    contains(action, "*")

    # No conditions specified
    not statement.Condition

    msg := sprintf(
        "Warning: IAM policy '%s' has broad permissions without conditions. Consider adding conditions like IP restrictions, MFA requirements, or time-based access.",
        [resource_change.address]
    )
}

# Deny S3 bucket policies that allow public access
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_s3_bucket_policy"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Check for public principal
    principal := statement.Principal
    principal == "*"

    # No restrictive conditions
    not statement.Condition

    msg := sprintf(
        "S3 bucket policy '%s' allows public access without conditions. This could expose sensitive data. Add conditions or restrict to specific principals.",
        [resource_change.address]
    )
}

# Warn about IAM users with inline policies
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_iam_user_policy"
    resource_change.change.actions[_] == "create"

    msg := sprintf(
        "Warning: Creating inline IAM user policy '%s'. AWS best practice recommends using managed policies and groups instead of inline user policies.",
        [resource_change.address]
    )
}

# Deny IAM policies that allow resource deletion without MFA
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Check for destructive actions
    some action in statement.Action
    destructive_actions := {
        "s3:DeleteBucket",
        "rds:DeleteDBInstance",
        "dynamodb:DeleteTable",
        "ec2:TerminateInstances",
    }
    some destructive in destructive_actions
    action_matches(action, destructive)

    # No MFA condition
    not statement.Condition.Bool["aws:MultiFactorAuthPresent"]

    msg := sprintf(
        "IAM policy '%s' allows destructive action '%s' without requiring MFA. Add MFA condition for sensitive operations.",
        [resource_change.address, action]
    )
}

# Warn about cross-account access without external ID
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_iam_role"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    assume_policy := parse_policy_document(resource.assume_role_policy)
    statements := get_statements(assume_policy)

    some statement in statements
    statement.Effect == "Allow"

    # Check if principal is from another account (contains account ID)
    principal := statement.Principal
    some aws_principal in principal.AWS
    contains(aws_principal, "arn:aws:iam::")

    # No external ID condition (recommended for cross-account access)
    not statement.Condition.StringEquals["sts:ExternalId"]

    msg := sprintf(
        "Warning: IAM role '%s' allows cross-account access without ExternalId condition. Add ExternalId for enhanced security in cross-account scenarios.",
        [resource_change.address]
    )
}

# Deny IAM policies that allow privilege escalation paths
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Dangerous combination: iam:PassRole + service launch permissions
    actions_set := {action | some action in statement.Action}

    # Check if policy allows both PassRole and service creation
    some pass_role_action in actions_set
    action_matches(pass_role_action, "iam:PassRole")

    # And allows launching services that can assume roles
    escalation_actions := {
        "lambda:CreateFunction",
        "ec2:RunInstances",
        "ecs:RunTask",
        "glue:CreateJob",
    }

    some escalation_action in escalation_actions
    some policy_action in actions_set
    action_matches(policy_action, escalation_action)

    msg := sprintf(
        "IAM policy '%s' allows privilege escalation path via iam:PassRole combined with service creation (%s). This is a security risk. Separate these permissions or add strict conditions.",
        [resource_change.address, escalation_action]
    )
}

# Warn about Lambda function resource policies allowing public invocation
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_lambda_permission"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Principal is a wildcard or public service
    resource.principal == "*"

    # No source ARN to restrict access
    not resource.source_arn

    msg := sprintf(
        "Warning: Lambda permission '%s' allows public invocation (*) without source ARN restriction. This could expose your function publicly.",
        [resource_change.address]
    )
}

# Deny KMS key policies that allow wildcard principals
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_kms_key"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # KMS keys have a policy attribute
    policy_doc := parse_policy_document(resource.policy)
    statements := get_statements(policy_doc)

    some statement in statements
    statement.Effect == "Allow"

    # Check for wildcard principals
    principal := statement.Principal
    principal.AWS == "*"

    # No conditions to restrict access
    not statement.Condition

    msg := sprintf(
        "KMS key '%s' has a policy allowing wildcard principal (*) without conditions. This could allow unauthorized decryption. Restrict to specific principals.",
        [resource_change.address]
    )
}

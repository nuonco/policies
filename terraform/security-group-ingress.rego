# Security Group Ingress Policy
#
# This policy prevents the creation of AWS security groups that allow unrestricted
# ingress from 0.0.0.0/0 (anywhere on the internet) on sensitive ports.
#
# Use Case:
# - Prevent accidental exposure of databases, SSH, RDP, and other sensitive services
# - Enforce security best practices for network access control
#
# Policy Type: terraform_module
# Engine: opa
#
# Example violation:
# ```hcl
# resource "aws_security_group" "db" {
#   ingress {
#     from_port   = 5432
#     to_port     = 5432
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]  # ⛔ This will be denied
#   }
# }
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# List of sensitive ports that should never be exposed to 0.0.0.0/0
sensitive_ports := {22, 23, 3306, 5432, 6379, 27017, 3389, 1433, 5984}

# Helper function to check if a port range overlaps with sensitive ports
port_overlaps_sensitive(from_port, to_port) if {
    some sensitive_port in sensitive_ports
    sensitive_port >= from_port
    sensitive_port <= to_port
}

# Deny security groups with unrestricted ingress on sensitive ports
deny contains msg if {
    # Get a resource change from the Terraform plan
    some resource_change in input.plan.resource_changes

    # Check if it's a security group or security group rule
    resource_change.type in ["aws_security_group", "aws_security_group_rule"]

    # Get the resource configuration after the change
    resource := resource_change.change.after

    # Check inline ingress rules (for aws_security_group)
    some ingress_rule in resource.ingress

    # Check if the rule allows access from 0.0.0.0/0
    some cidr in ingress_rule.cidr_blocks
    cidr == "0.0.0.0/0"

    # Check if the port range overlaps with sensitive ports
    port_overlaps_sensitive(ingress_rule.from_port, ingress_rule.to_port)

    msg := sprintf(
        "Security group '%s' allows unrestricted ingress from 0.0.0.0/0 on sensitive port(s) %d-%d. Restrict access to specific IP ranges.",
        [resource_change.address, ingress_rule.from_port, ingress_rule.to_port]
    )
}

# Deny standalone security group rules with unrestricted ingress
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_security_group_rule"

    resource := resource_change.change.after
    resource.type == "ingress"

    # Check if the rule allows access from 0.0.0.0/0
    some cidr in resource.cidr_blocks
    cidr == "0.0.0.0/0"

    # Check if the port range overlaps with sensitive ports
    port_overlaps_sensitive(resource.from_port, resource.to_port)

    msg := sprintf(
        "Security group rule '%s' allows unrestricted ingress from 0.0.0.0/0 on sensitive port(s) %d-%d. Restrict access to specific IP ranges.",
        [resource_change.address, resource.from_port, resource.to_port]
    )
}

# Warn about any unrestricted ingress, even on non-sensitive ports
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_security_group", "aws_security_group_rule"]

    resource := resource_change.change.after

    # Check inline ingress rules
    some ingress_rule in resource.ingress

    # Check if the rule allows access from 0.0.0.0/0
    some cidr in ingress_rule.cidr_blocks
    cidr == "0.0.0.0/0"

    # Only warn if it's NOT on a sensitive port (those are denied above)
    not port_overlaps_sensitive(ingress_rule.from_port, ingress_rule.to_port)

    msg := sprintf(
        "Warning: Security group '%s' allows unrestricted ingress from 0.0.0.0/0 on port(s) %d-%d. Consider restricting access.",
        [resource_change.address, ingress_rule.from_port, ingress_rule.to_port]
    )
}

# Warn about security groups with no description (security best practice)
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_security_group"
    resource := resource_change.change.after

    # Check if description is missing or empty
    not resource.description

    msg := sprintf(
        "Warning: Security group '%s' has no description. Add a description for better documentation and auditability.",
        [resource_change.address]
    )
}

# Alternative: Warn if description is empty string
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_security_group"
    resource := resource_change.change.after

    resource.description == ""

    msg := sprintf(
        "Warning: Security group '%s' has an empty description. Add a meaningful description.",
        [resource_change.address]
    )
}

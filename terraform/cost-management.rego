# Cost Management Policy
#
# This policy enforces cost control by preventing the creation of overly
# expensive resources and warning about cost increases.
#
# Use Case:
# - Prevent accidental provisioning of expensive instance types
# - Control cloud spending and prevent cost overruns
# - Enforce cost-conscious infrastructure decisions
# - Align infrastructure with budget constraints
#
# Policy Type: terraform_module
# Engine: opa
#
# Example violation:
# ```hcl
# resource "aws_instance" "web" {
#   instance_type = "m5.24xlarge"  # ⛔ Too expensive, will be denied
# }
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Define prohibited expensive EC2 instance types
# These are typically reserved for special use cases requiring approval
prohibited_ec2_instances := {
    # Metal instances
    "*.metal",
    # Very large instances (16xlarge and above)
    "*.16xlarge",
    "*.24xlarge",
    "*.32xlarge",
    # GPU instances (require special approval)
    "p2.*",
    "p3.*",
    "p4.*",
    "p5.*",
    "g4dn.*",
    "g5.*",
}

# Define allowed EC2 instance families for cost-sensitive environments
cost_optimized_ec2_families := {
    "t2", "t3", "t3a", "t4g",  # Burstable instances
    "m5", "m5a", "m6i", "m6a",  # General purpose (up to certain sizes)
    "c5", "c5a", "c6i", "c6a",  # Compute optimized
    "r5", "r5a", "r6i",          # Memory optimized
}

# Define prohibited expensive RDS instance types
prohibited_rds_instances := {
    "*.16xlarge",
    "*.24xlarge",
    "*.32xlarge",
}

# Helper: Extract instance family from instance type (e.g., "t3.micro" -> "t3")
get_instance_family(instance_type) := family if {
    parts := split(instance_type, ".")
    family := parts[0]
}

# Helper: Check if instance type matches a pattern
matches_pattern(instance_type, pattern) if {
    # Simple wildcard matching
    contains(pattern, "*")
    parts := split(pattern, "*")

    # If pattern is "prefix.*", check if instance starts with prefix
    count(parts) == 2
    parts[1] == ""
    startswith(instance_type, parts[0])
}

matches_pattern(instance_type, pattern) if {
    # Exact match
    not contains(pattern, "*")
    instance_type == pattern
}

# Deny creation of prohibited EC2 instances
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    instance_type := resource.instance_type

    # Check if instance type matches any prohibited pattern
    some prohibited in prohibited_ec2_instances
    matches_pattern(instance_type, prohibited)

    msg := sprintf(
        "EC2 instance '%s' uses prohibited instance type '%s'. Use smaller instance types or request approval for exceptions.",
        [resource_change.address, instance_type]
    )
}

# Deny creation of prohibited RDS instances
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    instance_class := resource.instance_class

    # Check if instance class matches any prohibited pattern
    some prohibited in prohibited_rds_instances
    matches_pattern(instance_class, prohibited)

    msg := sprintf(
        "RDS instance '%s' uses prohibited instance class '%s'. Use smaller instance classes or request approval for exceptions.",
        [resource_change.address, instance_class]
    )
}

# Warn about large EC2 instance types
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    instance_type := resource.instance_type

    # Check for large instances (2xlarge, 4xlarge, 8xlarge)
    some size in {"2xlarge", "4xlarge", "8xlarge", "12xlarge"}
    endswith(instance_type, size)

    msg := sprintf(
        "Warning: EC2 instance '%s' uses large instance type '%s'. This may incur significant costs. Consider using smaller instances with auto-scaling.",
        [resource_change.address, instance_type]
    )
}

# Warn about RDS storage size
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Warn if allocated storage is very large
    resource.allocated_storage > 1000  # 1TB

    msg := sprintf(
        "Warning: RDS instance '%s' has %d GB of allocated storage. Consider if this capacity is necessary for cost optimization.",
        [resource_change.address, resource.allocated_storage]
    )
}

# Deny provisioned IOPS without justification
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Using provisioned IOPS (io1 or io2)
    resource.storage_type in ["io1", "io2"]

    # IOPS is very high
    resource.iops > 10000

    msg := sprintf(
        "RDS instance '%s' uses provisioned IOPS storage with %d IOPS. This is expensive. Use gp3 storage unless high IOPS is required.",
        [resource_change.address, resource.iops]
    )
}

# Warn about NAT Gateway creation (expensive for high data transfer)
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_nat_gateway"
    resource_change.change.actions[_] == "create"

    msg := sprintf(
        "Warning: NAT Gateway '%s' will incur hourly charges plus data transfer costs. Consider using VPC endpoints or NAT instances for cost savings.",
        [resource_change.address]
    )
}

# Warn about multiple NAT Gateways
warn contains msg if {
    # Count NAT gateways being created
    nat_gateways := [gw |
        some resource_change in input.plan.resource_changes
        resource_change.type == "aws_nat_gateway"
        resource_change.change.actions[_] == "create"
        gw := resource_change
    ]

    count(nat_gateways) > 1

    msg := sprintf(
        "Warning: Creating %d NAT Gateways. Each gateway incurs hourly charges. Consider if multiple NAT Gateways are necessary for your high-availability requirements.",
        [count(nat_gateways)]
    )
}

# Deny ElastiCache clusters with excessive node count
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_elasticache_replication_group"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Too many replicas for typical use
    resource.number_cache_clusters > 6

    msg := sprintf(
        "ElastiCache replication group '%s' has %d cache clusters. This is expensive. Use 3-6 clusters for high availability unless special requirements exist.",
        [resource_change.address, resource.number_cache_clusters]
    )
}

# Warn about ElastiCache node types
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_elasticache_cluster", "aws_elasticache_replication_group"]
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after
    node_type := resource.node_type

    # Large cache nodes
    some size in {"xlarge", "2xlarge", "4xlarge"}
    contains(node_type, size)

    msg := sprintf(
        "Warning: ElastiCache resource '%s' uses large node type '%s'. Consider using smaller nodes unless high memory is required.",
        [resource_change.address, node_type]
    )
}

# Deny creation of multiple availability zones without environment check
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_db_instance"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Multi-AZ is enabled
    resource.multi_az == true

    # Check tags to see if this is a development environment
    tags := resource.tags
    env := tags["Environment"]
    env in {"development", "dev", "test"}

    msg := sprintf(
        "RDS instance '%s' has multi-AZ enabled in %s environment. Multi-AZ doubles costs and is typically not needed for non-production.",
        [resource_change.address, env]
    )
}

# Warn about DynamoDB provisioned capacity mode
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_dynamodb_table"
    resource_change.change.actions[_] in ["create", "update"]

    resource := resource_change.change.after

    # Using provisioned capacity
    resource.billing_mode == "PROVISIONED"

    # High provisioned capacity
    resource.read_capacity > 100

    msg := sprintf(
        "Warning: DynamoDB table '%s' uses provisioned capacity with %d read capacity units. Consider using PAY_PER_REQUEST (on-demand) for cost optimization unless traffic is predictable.",
        [resource_change.address, resource.read_capacity]
    )
}

# Deny creation of Load Balancers in development environments
deny contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type in ["aws_lb", "aws_alb", "aws_elb"]
    resource_change.change.actions[_] == "create"

    resource := resource_change.change.after

    # Check environment tag
    tags := resource.tags
    env := tags["Environment"]
    env in {"development", "dev"}

    msg := sprintf(
        "Load Balancer '%s' creation in development environment. Load Balancers incur hourly charges. Use port-forwarding or ingress controllers instead for dev environments.",
        [resource_change.address]
    )
}

# Warn about Redshift clusters in non-production
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_redshift_cluster"
    resource_change.change.actions[_] == "create"

    resource := resource_change.change.after

    # Check environment
    tags := resource.tags
    env := tags["Environment"]
    env in {"development", "dev", "test", "staging"}

    msg := sprintf(
        "Warning: Redshift cluster '%s' in %s environment. Redshift is expensive for non-production use. Consider using Athena or smaller analytics solutions for testing.",
        [resource_change.address, env]
    )
}

# Warn about EC2 instances without auto-scaling
warn contains msg if {
    some resource_change in input.plan.resource_changes
    resource_change.type == "aws_instance"
    resource_change.change.actions[_] == "create"

    # Check if this is a standalone instance (not part of ASG)
    # We can't directly check ASG membership in the plan, but we can warn
    # about instances that might benefit from auto-scaling

    resource := resource_change.change.after
    instance_type := resource.instance_type

    # Only for instances that are not burstable (ASG makes more sense for steady workloads)
    not startswith(instance_type, "t2.")
    not startswith(instance_type, "t3.")
    not startswith(instance_type, "t4g.")

    msg := sprintf(
        "Warning: EC2 instance '%s' (type: %s) is being created. Consider using Auto Scaling Groups for cost optimization and high availability.",
        [resource_change.address, instance_type]
    )
}

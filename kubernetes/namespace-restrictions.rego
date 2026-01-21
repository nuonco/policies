# Namespace Restrictions Policy
#
# This policy enforces proper namespace usage and prevents deployment to
# default or system namespaces, promoting better organization and security.
#
# Use Case:
# - Prevent accidental deployment to default namespace
# - Protect system namespaces from user workloads
# - Enforce namespace naming conventions
# - Support multi-tenancy and workload isolation
#
# Policy Type: kubernetes_manifest
# Engine: opa
#
# Example violation:
# ```yaml
# apiVersion: v1
# kind: Pod
# metadata:
#   name: my-app
#   namespace: default  # ⛔ Will be denied
# spec:
#   containers:
#   - name: app
#     image: nginx
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# System and reserved namespaces that should not be used for user workloads
restricted_namespaces := {
    "default",
    "kube-system",
    "kube-public",
    "kube-node-lease",
}

# Additional restricted patterns for system namespaces
restricted_namespace_prefixes := {
    "kube-",
}

# Resource types that should have explicit namespaces
namespaced_resources := {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "Service",
    "Ingress",
    "ConfigMap",
    "Secret",
    "PersistentVolumeClaim",
    "ServiceAccount",
    "Role",
    "RoleBinding",
}

# Deny resources deployed to restricted namespaces
deny contains msg if {
    input.review.kind.kind in namespaced_resources

    # Get the namespace
    namespace := object.get(input.review.object.metadata, "namespace", "default")

    # Check if it's a restricted namespace
    namespace in restricted_namespaces

    msg := sprintf(
        "%s '%s' is being deployed to restricted namespace '%s'. Use a dedicated application namespace instead.",
        [input.review.kind.kind, input.review.object.metadata.name, namespace]
    )
}

# Deny resources deployed to namespaces with system prefixes
deny contains msg if {
    input.review.kind.kind in namespaced_resources

    namespace := object.get(input.review.object.metadata, "namespace", "default")

    # Check if namespace starts with a restricted prefix
    some prefix in restricted_namespace_prefixes
    startswith(namespace, prefix)

    msg := sprintf(
        "%s '%s' is being deployed to system namespace '%s' (prefix: %s). System namespaces are reserved for Kubernetes components.",
        [input.review.kind.kind, input.review.object.metadata.name, namespace, prefix]
    )
}

# Warn about resources without explicit namespace (will default to 'default')
warn contains msg if {
    input.review.kind.kind in namespaced_resources

    # No namespace specified in metadata
    not input.review.object.metadata.namespace

    msg := sprintf(
        "Warning: %s '%s' does not specify a namespace and will default to 'default'. Always specify an explicit namespace.",
        [input.review.kind.kind, input.review.object.metadata.name]
    )
}

# Enforce namespace naming convention (lowercase, alphanumeric, hyphens)
warn contains msg if {
    input.review.kind.kind in namespaced_resources

    namespace := object.get(input.review.object.metadata, "namespace", "default")

    # Check if namespace follows naming convention
    not is_valid_namespace_name(namespace)

    msg := sprintf(
        "Warning: %s '%s' uses namespace '%s' which may not follow naming conventions. Use lowercase alphanumeric characters and hyphens only.",
        [input.review.kind.kind, input.review.object.metadata.name, namespace]
    )
}

# Helper to validate namespace name format
is_valid_namespace_name(name) if {
    # Must be lowercase
    lower(name) == name

    # Must not start or end with hyphen
    not startswith(name, "-")
    not endswith(name, "-")

    # For simplicity, we check it doesn't contain invalid characters
    # In a real implementation, you'd use regex to validate fully
    not contains(name, "_")
    not contains(name, ".")
    not contains(name, " ")
}

# Deny Namespace resources with restricted names
deny contains msg if {
    input.review.kind.kind == "Namespace"

    name := input.review.object.metadata.name

    # Check if trying to create a restricted namespace
    name in restricted_namespaces

    msg := sprintf(
        "Cannot create Namespace '%s' - this is a reserved namespace name.",
        [name]
    )
}

# Deny Namespace resources with system prefixes
deny contains msg if {
    input.review.kind.kind == "Namespace"

    name := input.review.object.metadata.name

    # Check if namespace name starts with a restricted prefix
    some prefix in restricted_namespace_prefixes
    startswith(name, prefix)

    msg := sprintf(
        "Cannot create Namespace '%s' - names starting with '%s' are reserved for Kubernetes system components.",
        [name, prefix]
    )
}

# Warn about very long namespace names
warn contains msg if {
    input.review.kind.kind == "Namespace"

    name := input.review.object.metadata.name

    # Namespace name is very long (Kubernetes allows up to 63 characters)
    count(name) > 40

    msg := sprintf(
        "Warning: Namespace '%s' has a very long name (%d characters). Consider using a shorter name for better readability.",
        [name, count(name)]
    )
}

# Recommend namespace labels for organization
warn contains msg if {
    input.review.kind.kind == "Namespace"

    # Check if namespace has recommended labels
    labels := object.get(input.review.object.metadata, "labels", {})

    # Missing important organizational labels
    not labels["environment"]
    not labels["team"]

    msg := sprintf(
        "Warning: Namespace '%s' is missing recommended labels. Consider adding 'environment' and 'team' labels for better organization.",
        [input.review.object.metadata.name]
    )
}

# Deny ServiceAccounts in default namespace
deny contains msg if {
    input.review.kind.kind == "ServiceAccount"

    namespace := object.get(input.review.object.metadata, "namespace", "default")
    namespace == "default"

    # Not the default ServiceAccount (which is system-managed)
    input.review.object.metadata.name != "default"

    msg := sprintf(
        "ServiceAccount '%s' cannot be created in 'default' namespace. Use a dedicated application namespace.",
        [input.review.object.metadata.name]
    )
}

# Warn about Secrets and ConfigMaps in default namespace
warn contains msg if {
    input.review.kind.kind in {"Secret", "ConfigMap"}

    namespace := object.get(input.review.object.metadata, "namespace", "default")
    namespace == "default"

    msg := sprintf(
        "Warning: %s '%s' is in 'default' namespace. Consider organizing configuration resources in dedicated namespaces.",
        [input.review.kind.kind, input.review.object.metadata.name]
    )
}

# Deny RoleBindings that grant permissions across namespaces inappropriately
deny contains msg if {
    input.review.kind.kind == "RoleBinding"

    namespace := object.get(input.review.object.metadata, "namespace", "default")

    # RoleBinding references a ClusterRole (which may have cluster-wide permissions)
    input.review.object.roleRef.kind == "ClusterRole"

    # In a sensitive namespace
    namespace in restricted_namespaces

    msg := sprintf(
        "RoleBinding '%s' in restricted namespace '%s' references ClusterRole '%s'. This may grant excessive permissions.",
        [input.review.object.metadata.name, namespace, input.review.object.roleRef.name]
    )
}

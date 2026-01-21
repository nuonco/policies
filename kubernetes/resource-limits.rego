# Resource Limits and Requests Policy
#
# This policy enforces that all containers have resource requests and limits defined,
# preventing resource exhaustion and ensuring predictable scheduling and performance.
#
# Use Case:
# - Prevent resource starvation (CPU, memory)
# - Enable proper pod scheduling and quality of service
# - Control costs by preventing runaway resource consumption
# - Comply with cluster resource management policies
#
# Policy Type: kubernetes_manifest
# Engine: opa
#
# Example violation:
# ```yaml
# apiVersion: v1
# kind: Pod
# metadata:
#   name: resource-hungry
# spec:
#   containers:
#   - name: app
#     image: nginx
#     # Missing resources.requests and resources.limits ⛔ Will be denied
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Resource types that contain pod specs
pod_spec_resources := {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
}

# Helper to get pod spec from different resource types
get_pod_spec(obj) := obj.spec if {
    input.review.kind.kind == "Pod"
}

get_pod_spec(obj) := obj.spec.template.spec if {
    input.review.kind.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}
}

get_pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
    input.review.kind.kind == "CronJob"
}

get_pod_spec(obj) := obj.spec.template.spec if {
    input.review.kind.kind == "Job"
}

# Deny containers without CPU requests
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # No CPU request defined
    not container.resources.requests.cpu

    msg := sprintf(
        "%s '%s' container '%s' does not have CPU requests defined. Set resources.requests.cpu to ensure proper scheduling.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Deny containers without memory requests
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # No memory request defined
    not container.resources.requests.memory

    msg := sprintf(
        "%s '%s' container '%s' does not have memory requests defined. Set resources.requests.memory to ensure proper scheduling.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Deny containers without CPU limits
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # No CPU limit defined
    not container.resources.limits.cpu

    msg := sprintf(
        "%s '%s' container '%s' does not have CPU limits defined. Set resources.limits.cpu to prevent CPU starvation.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Deny containers without memory limits
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # No memory limit defined
    not container.resources.limits.memory

    msg := sprintf(
        "%s '%s' container '%s' does not have memory limits defined. Set resources.limits.memory to prevent OOM issues.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Warn about very large CPU limits (may indicate misconfiguration)
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # CPU limit is very large (more than 8 cores)
    cpu_limit := parse_cpu(container.resources.limits.cpu)
    cpu_limit > 8000  # 8000 millicores = 8 CPUs

    msg := sprintf(
        "Warning: %s '%s' container '%s' has very large CPU limit (%s). Verify this is intentional.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, container.resources.limits.cpu]
    )
}

# Warn about very large memory limits (may indicate misconfiguration)
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Memory limit is very large (more than 16Gi)
    memory_limit := parse_memory(container.resources.limits.memory)
    memory_limit > 17179869184  # 16Gi in bytes

    msg := sprintf(
        "Warning: %s '%s' container '%s' has very large memory limit (%s). Verify this is intentional.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, container.resources.limits.memory]
    )
}

# Warn when limits are much larger than requests (poor resource utilization)
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Both CPU request and limit are defined
    cpu_request := parse_cpu(container.resources.requests.cpu)
    cpu_limit := parse_cpu(container.resources.limits.cpu)

    # Limit is more than 4x the request (potential for poor QoS)
    cpu_limit > cpu_request * 4

    msg := sprintf(
        "Warning: %s '%s' container '%s' has CPU limit (%s) much larger than request (%s). Consider adjusting for better QoS classification.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name,
         container.resources.limits.cpu, container.resources.requests.cpu]
    )
}

# Warn when memory limits are much larger than requests
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Both memory request and limit are defined
    memory_request := parse_memory(container.resources.requests.memory)
    memory_limit := parse_memory(container.resources.limits.memory)

    # Limit is more than 4x the request
    memory_limit > memory_request * 4

    msg := sprintf(
        "Warning: %s '%s' container '%s' has memory limit (%s) much larger than request (%s). Consider adjusting for better QoS classification.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name,
         container.resources.limits.memory, container.resources.requests.memory]
    )
}

# Helper: Parse CPU resource string to millicores
parse_cpu(cpu_str) := result if {
    # Handle millicores (e.g., "100m")
    endswith(cpu_str, "m")
    trimmed := trim_suffix(cpu_str, "m")
    result := to_number(trimmed)
}

parse_cpu(cpu_str) := result if {
    # Handle whole cores (e.g., "2" or "0.5")
    not endswith(cpu_str, "m")
    cores := to_number(cpu_str)
    result := cores * 1000  # Convert to millicores
}

# Helper: Parse memory resource string to bytes
parse_memory(memory_str) := result if {
    # Handle Ki (kibibytes)
    endswith(memory_str, "Ki")
    trimmed := trim_suffix(memory_str, "Ki")
    result := to_number(trimmed) * 1024
}

parse_memory(memory_str) := result if {
    # Handle Mi (mebibytes)
    endswith(memory_str, "Mi")
    trimmed := trim_suffix(memory_str, "Mi")
    result := to_number(trimmed) * 1048576
}

parse_memory(memory_str) := result if {
    # Handle Gi (gibibytes)
    endswith(memory_str, "Gi")
    trimmed := trim_suffix(memory_str, "Gi")
    result := to_number(trimmed) * 1073741824
}

parse_memory(memory_str) := result if {
    # Handle plain bytes
    not contains(memory_str, "Ki")
    not contains(memory_str, "Mi")
    not contains(memory_str, "Gi")
    result := to_number(memory_str)
}

# Check init containers for resource requirements
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.initContainers

    # Missing any resource specification
    not container.resources.requests.cpu
    not container.resources.requests.memory

    msg := sprintf(
        "%s '%s' init container '%s' does not have resource requests defined. Init containers also need resource specifications.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Warn about tiny resource requests (may indicate placeholder values)
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # CPU request is very small (less than 10m)
    cpu_request := parse_cpu(container.resources.requests.cpu)
    cpu_request < 10

    msg := sprintf(
        "Warning: %s '%s' container '%s' has very small CPU request (%s). This may cause scheduling issues or indicate a placeholder value.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, container.resources.requests.cpu]
    )
}

# Warn about tiny memory requests
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Memory request is very small (less than 4Mi)
    memory_request := parse_memory(container.resources.requests.memory)
    memory_request < 4194304  # 4Mi in bytes

    msg := sprintf(
        "Warning: %s '%s' container '%s' has very small memory request (%s). This is unlikely to be sufficient for most applications.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, container.resources.requests.memory]
    )
}

# Info: Suggest ephemeral storage limits for stateful workloads
warn contains msg if {
    input.review.kind.kind in {"StatefulSet", "DaemonSet"}

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # No ephemeral storage limit defined
    not container.resources.limits["ephemeral-storage"]

    msg := sprintf(
        "Info: %s '%s' container '%s' does not have ephemeral storage limits. Consider adding resources.limits.ephemeral-storage for stateful workloads.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

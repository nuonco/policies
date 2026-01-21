# Container Security Context Policy
#
# This policy enforces security best practices for container security contexts,
# preventing containers from running as root and ensuring proper security settings.
#
# Use Case:
# - Prevent privilege escalation vulnerabilities
# - Enforce principle of least privilege for containers
# - Comply with security frameworks (CIS Kubernetes Benchmark, Pod Security Standards)
# - Protect host systems from compromised containers
#
# Policy Type: kubernetes_manifest
# Engine: opa
#
# Example violation:
# ```yaml
# apiVersion: v1
# kind: Pod
# metadata:
#   name: insecure-pod
# spec:
#   containers:
#   - name: app
#     image: nginx
#     # Missing securityContext or runAsNonRoot ⛔ Will be denied
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

# Deny containers running as root
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Container doesn't explicitly set runAsNonRoot
    not container.securityContext.runAsNonRoot

    # And pod-level securityContext doesn't set it either
    not pod_spec.securityContext.runAsNonRoot

    msg := sprintf(
        "%s '%s' has container '%s' that may run as root. Set securityContext.runAsNonRoot = true at container or pod level.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Deny containers explicitly running as UID 0 (root)
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Container explicitly sets runAsUser to 0
    container.securityContext.runAsUser == 0

    msg := sprintf(
        "%s '%s' has container '%s' explicitly configured to run as root (UID 0). Use a non-root user.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Deny containers with privileged mode enabled
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    container.securityContext.privileged == true

    msg := sprintf(
        "%s '%s' has container '%s' running in privileged mode. This grants all host capabilities and is dangerous.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Deny containers with allowPrivilegeEscalation enabled
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # allowPrivilegeEscalation is true or not set (defaults to true)
    container.securityContext.allowPrivilegeEscalation != false

    msg := sprintf(
        "%s '%s' has container '%s' with allowPrivilegeEscalation not set to false. This allows processes to gain more privileges than their parent.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Warn about containers without read-only root filesystem
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # readOnlyRootFilesystem is not set to true
    not container.securityContext.readOnlyRootFilesystem

    msg := sprintf(
        "Warning: %s '%s' container '%s' does not have read-only root filesystem. Consider setting securityContext.readOnlyRootFilesystem = true for better security.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Warn about containers with added capabilities
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Check if capabilities are added
    count(container.securityContext.capabilities.add) > 0

    caps := concat(", ", container.securityContext.capabilities.add)

    msg := sprintf(
        "Warning: %s '%s' container '%s' adds Linux capabilities: %s. Ensure these are necessary.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, caps]
    )
}

# Deny containers without dropping ALL capabilities and adding only required ones
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Check if ALL capabilities are not dropped
    not capabilities_dropped_all(container)

    msg := sprintf(
        "%s '%s' container '%s' does not drop ALL capabilities. Set securityContext.capabilities.drop = ['ALL'] and add only required capabilities.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Helper to check if ALL capabilities are dropped
capabilities_dropped_all(container) if {
    some cap in container.securityContext.capabilities.drop
    cap == "ALL"
}

# Warn about host namespace usage
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)

    # Check for any host namespace usage
    host_settings := [
        {"name": "hostNetwork", "value": pod_spec.hostNetwork},
        {"name": "hostPID", "value": pod_spec.hostPID},
        {"name": "hostIPC", "value": pod_spec.hostIPC},
    ]

    some setting in host_settings
    setting.value == true

    msg := sprintf(
        "%s '%s' uses %s = true. This allows access to host-level resources and is a security risk.",
        [input.review.kind.kind, input.review.object.metadata.name, setting.name]
    )
}

# Warn about containers mounting host paths
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some volume in pod_spec.volumes

    # Volume is a hostPath
    volume.hostPath

    msg := sprintf(
        "Warning: %s '%s' mounts host path '%s' via volume '%s'. This grants access to host filesystem and may be a security risk.",
        [input.review.kind.kind, input.review.object.metadata.name, volume.hostPath.path, volume.name]
    )
}

# Deny containers without seccomp profile
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.containers

    # Container doesn't have seccomp profile
    not container.securityContext.seccompProfile

    # Pod-level seccomp profile is also not set
    not pod_spec.securityContext.seccompProfile

    msg := sprintf(
        "Warning: %s '%s' container '%s' does not have a seccomp profile. Consider setting securityContext.seccompProfile.type = 'RuntimeDefault' for syscall filtering.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Check init containers as well
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.initContainers

    not container.securityContext.runAsNonRoot
    not pod_spec.securityContext.runAsNonRoot

    msg := sprintf(
        "%s '%s' has init container '%s' that may run as root. Set securityContext.runAsNonRoot = true.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Check ephemeral containers as well (for debugging)
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in pod_spec.ephemeralContainers

    not container.securityContext.runAsNonRoot

    msg := sprintf(
        "Warning: %s '%s' has ephemeral container '%s' that may run as root. Even debugging containers should follow security best practices.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

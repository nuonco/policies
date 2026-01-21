# Container Image Security Policy
#
# This policy enforces security best practices for container images,
# including registry restrictions, tag requirements, and vulnerability management.
#
# Use Case:
# - Enforce use of trusted container registries
# - Prevent use of latest/mutable tags
# - Require image digests for reproducibility
# - Block known vulnerable base images
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
# spec:
#   containers:
#   - name: app
#     image: nginx:latest  # ⛔ Using 'latest' tag will be denied
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

# Approved container registries
approved_registries := {
    "docker.io",           # Docker Hub (consider restricting further)
    "ghcr.io",             # GitHub Container Registry
    "gcr.io",              # Google Container Registry
    "*.ecr.*.amazonaws.com", # AWS ECR (wildcard for regions)
    "quay.io",             # Red Hat Quay
    "registry.k8s.io",     # Kubernetes official images
}

# Known vulnerable or discouraged base images
blocked_images := {
    "ubuntu:latest",
    "debian:latest",
    "alpine:latest",
    "centos:latest",
    "fedora:latest",
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

# Get all containers (including init and ephemeral)
get_all_containers(pod_spec) := containers if {
    regular := array.concat(
        object.get(pod_spec, "containers", []),
        object.get(pod_spec, "initContainers", [])
    )
    containers := array.concat(regular, object.get(pod_spec, "ephemeralContainers", []))
}

# Deny containers using 'latest' tag
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    # Image uses 'latest' tag or no tag (defaults to latest)
    image := container.image
    endswith(image, ":latest")

    msg := sprintf(
        "%s '%s' container '%s' uses ':latest' tag for image '%s'. Use specific version tags for reproducibility.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

# Deny containers without explicit tag
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image

    # Image has no tag (will default to latest)
    not contains(image, ":")
    not contains(image, "@")  # And not using digest

    msg := sprintf(
        "%s '%s' container '%s' uses image '%s' without a tag. Always specify explicit version tags.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

# Warn about containers not using image digests
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image

    # Image uses tag but not digest
    contains(image, ":")
    not contains(image, "@sha256:")

    msg := sprintf(
        "Warning: %s '%s' container '%s' uses tag-based image '%s'. Consider using digest (@sha256:...) for immutability.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

# Deny containers from unapproved registries
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image
    registry := get_registry(image)

    # Check if registry is approved
    not is_approved_registry(registry)

    msg := sprintf(
        "%s '%s' container '%s' uses image from unapproved registry '%s'. Use approved registries: %v",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, registry, approved_registries]
    )
}

# Deny containers using blocked/vulnerable images
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image

    # Check against blocked images
    some blocked in blocked_images
    startswith(image, blocked)

    msg := sprintf(
        "%s '%s' container '%s' uses blocked image '%s'. This image is known to be vulnerable or discouraged.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

# Helper to extract registry from image string
get_registry(image) := registry if {
    # Image format: registry/repo/image:tag or registry/repo/image@digest
    parts := split(image, "/")
    count(parts) >= 2

    # First part is the registry
    registry := parts[0]
}

get_registry(image) := "docker.io" if {
    # No registry specified, defaults to Docker Hub
    parts := split(image, "/")
    count(parts) == 1
}

get_registry(image) := "docker.io" if {
    # Library images (e.g., nginx:1.21) default to Docker Hub
    parts := split(image, "/")
    count(parts) == 2
    not contains(parts[0], ".")
}

# Helper to check if registry is approved
is_approved_registry(registry) if {
    # Exact match
    registry in approved_registries
}

is_approved_registry(registry) if {
    # Wildcard match for ECR
    some approved in approved_registries
    contains(approved, "*")

    # Simple wildcard matching for ECR pattern
    approved == "*.ecr.*.amazonaws.com"
    contains(registry, ".ecr.")
    contains(registry, ".amazonaws.com")
}

# Warn about containers using public Docker Hub images
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image
    registry := get_registry(image)

    # Using Docker Hub
    registry == "docker.io"

    # Not an official library image or verified publisher
    not is_official_dockerhub_image(image)

    msg := sprintf(
        "Warning: %s '%s' container '%s' uses public Docker Hub image '%s'. Consider using vetted images from approved registries.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

# Helper to check if Docker Hub image is from official library
is_official_dockerhub_image(image) if {
    # Official library images have specific patterns
    parts := split(image, "/")
    count(parts) <= 2  # library/nginx or nginx

    # Common official images
    official_prefixes := {"library/", "nginx", "redis", "postgres", "mysql", "mongo", "node", "python", "golang"}
    some prefix in official_prefixes
    startswith(image, prefix)
}

# Deny containers with imagePullPolicy: Always in production
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    # imagePullPolicy is Always
    container.imagePullPolicy == "Always"

    # Check if this is production environment
    labels := object.get(input.review.object.metadata, "labels", {})
    env := object.get(labels, "environment", "")
    env in {"production", "prod"}

    msg := sprintf(
        "Warning: %s '%s' container '%s' uses imagePullPolicy: Always in production. Use IfNotPresent with digests for consistency.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Warn about missing image pull secrets for private registries
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image
    registry := get_registry(image)

    # Using a private registry (ECR, GCR, etc.)
    registry != "docker.io"
    registry != "registry.k8s.io"

    # No image pull secrets defined
    not pod_spec.imagePullSecrets

    msg := sprintf(
        "Warning: %s '%s' uses private registry '%s' but has no imagePullSecrets. Ensure image pull secrets are configured.",
        [input.review.kind.kind, input.review.object.metadata.name, registry]
    )
}

# Deny containers using Alpine Linux without specific version
deny contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image

    # Using Alpine base without specific version
    contains(image, "alpine:")
    endswith(image, ":alpine")

    msg := sprintf(
        "%s '%s' container '%s' uses Alpine Linux without specific version. Use 'alpine:3.18' or similar for reproducibility.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name]
    )
}

# Warn about very old or EOL base images
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image

    # Known old/EOL versions
    old_patterns := {
        "ubuntu:16.04",
        "ubuntu:18.04",
        "debian:8",
        "debian:9",
        "node:10",
        "node:12",
        "python:2.7",
        "alpine:3.8",
        "alpine:3.9",
    }

    some old in old_patterns
    contains(image, old)

    msg := sprintf(
        "Warning: %s '%s' container '%s' uses potentially outdated base image '%s'. Consider updating to a supported version.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

# Warn about large base images
warn contains msg if {
    input.review.kind.kind in pod_spec_resources

    pod_spec := get_pod_spec(input.review.object)
    some container in get_all_containers(pod_spec)

    image := container.image

    # Images known to be large
    large_bases := {
        "ubuntu",
        "debian",
        "centos",
        "fedora",
    }

    some large in large_bases
    startswith(image, large)

    msg := sprintf(
        "Info: %s '%s' container '%s' uses base image '%s'. Consider using distroless or Alpine images for smaller attack surface and faster pulls.",
        [input.review.kind.kind, input.review.object.metadata.name, container.name, image]
    )
}

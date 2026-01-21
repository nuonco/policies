# Ingress Security Policy
#
# This policy enforces security best practices for Ingress resources,
# ensuring TLS configuration and preventing insecure ingress patterns.
#
# Use Case:
# - Enforce HTTPS/TLS for all external traffic
# - Prevent insecure HTTP-only ingress routes
# - Validate ingress annotations for security settings
# - Comply with security frameworks requiring encryption in transit
#
# Policy Type: kubernetes_manifest
# Engine: opa
#
# Example violation:
# ```yaml
# apiVersion: networking.k8s.io/v1
# kind: Ingress
# metadata:
#   name: my-app
# spec:
#   rules:
#   - host: example.com
#     http:
#       paths:
#       - path: /
#         pathType: Prefix
#         backend:
#           service:
#             name: my-service
#             port:
#               number: 80
#   # Missing tls section ⛔ Will be denied
# ```

package nuon

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny Ingress resources without TLS configuration
deny contains msg if {
    input.review.kind.kind == "Ingress"

    # Ingress has rules but no TLS section
    count(input.review.object.spec.rules) > 0
    not input.review.object.spec.tls

    msg := sprintf(
        "Ingress '%s' does not have TLS configured. All ingress resources must use HTTPS. Add spec.tls section with certificate configuration.",
        [input.review.object.metadata.name]
    )
}

# Deny Ingress resources with empty TLS section
deny contains msg if {
    input.review.kind.kind == "Ingress"

    # TLS section exists but is empty
    count(input.review.object.spec.tls) == 0

    msg := sprintf(
        "Ingress '%s' has empty TLS configuration. Specify at least one TLS certificate.",
        [input.review.object.metadata.name]
    )
}

# Warn about Ingress rules with hosts not covered by TLS
warn contains msg if {
    input.review.kind.kind == "Ingress"

    # Get all hosts from rules
    some rule in input.review.object.spec.rules
    rule_host := rule.host

    # Get all hosts from TLS
    tls_hosts := {host |
        some tls_entry in input.review.object.spec.tls
        some host in tls_entry.hosts
    }

    # Rule host is not in TLS hosts
    not rule_host in tls_hosts

    msg := sprintf(
        "Warning: Ingress '%s' has rule for host '%s' but this host is not covered by any TLS configuration.",
        [input.review.object.metadata.name, rule_host]
    )
}

# Warn about Ingress without SSL redirect annotation
warn contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Check common SSL redirect annotations for popular ingress controllers
    not annotations["nginx.ingress.kubernetes.io/ssl-redirect"]
    not annotations["kubernetes.io/ingress.allow-http"]
    not annotations["ingress.kubernetes.io/ssl-redirect"]

    msg := sprintf(
        "Warning: Ingress '%s' does not have SSL redirect configured. Consider adding 'nginx.ingress.kubernetes.io/ssl-redirect: \"true\"' annotation to force HTTPS.",
        [input.review.object.metadata.name]
    )
}

# Deny Ingress explicitly allowing HTTP
deny contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Check if HTTP is explicitly allowed (common patterns)
    annotations["nginx.ingress.kubernetes.io/ssl-redirect"] == "false"

    msg := sprintf(
        "Ingress '%s' explicitly disables SSL redirect. HTTP-only ingress is not allowed.",
        [input.review.object.metadata.name]
    )
}

# Deny Ingress with weak TLS versions
deny contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Check for weak TLS version specifications (TLS 1.0, TLS 1.1)
    tls_versions := [
        annotations["nginx.ingress.kubernetes.io/ssl-protocols"],
        annotations["ingress.kubernetes.io/ssl-protocols"],
    ]

    some version in tls_versions
    version != null

    # Contains weak TLS versions
    weak_tls := {"TLSv1", "TLSv1.0", "TLSv1.1"}
    some weak in weak_tls
    contains(version, weak)

    msg := sprintf(
        "Ingress '%s' allows weak TLS versions (%s). Use TLSv1.2 and TLSv1.3 only.",
        [input.review.object.metadata.name, version]
    )
}

# Warn about Ingress without rate limiting
warn contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Check for rate limiting annotations (nginx ingress controller)
    not annotations["nginx.ingress.kubernetes.io/rate-limit"]
    not annotations["nginx.ingress.kubernetes.io/limit-rps"]

    msg := sprintf(
        "Warning: Ingress '%s' does not have rate limiting configured. Consider adding rate limiting annotations to prevent abuse.",
        [input.review.object.metadata.name]
    )
}

# Warn about Ingress without authentication
warn contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Check for common authentication annotations
    not annotations["nginx.ingress.kubernetes.io/auth-type"]
    not annotations["nginx.ingress.kubernetes.io/auth-url"]
    not annotations["cert-manager.io/cluster-issuer"]

    # And not marked as public
    not annotations["nuon.co/public"] == "true"

    msg := sprintf(
        "Info: Ingress '%s' has no authentication configured. If this is not a public endpoint, consider adding authentication.",
        [input.review.object.metadata.name]
    )
}

# Deny Ingress with default backend without TLS
deny contains msg if {
    input.review.kind.kind == "Ingress"

    # Has default backend
    input.review.object.spec.defaultBackend

    # No TLS configured
    not input.review.object.spec.tls

    msg := sprintf(
        "Ingress '%s' has a default backend but no TLS configuration. Even default backends must use HTTPS.",
        [input.review.object.metadata.name]
    )
}

# Warn about wildcard TLS certificates
warn contains msg if {
    input.review.kind.kind == "Ingress"

    some tls_entry in input.review.object.spec.tls
    some host in tls_entry.hosts

    # Check for wildcard certificate
    startswith(host, "*.")

    msg := sprintf(
        "Warning: Ingress '%s' uses wildcard TLS host '%s'. Wildcard certificates may pose security risks. Consider using specific hostnames.",
        [input.review.object.metadata.name, host]
    )
}

# Warn about Ingress without CORS configuration
warn contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Ingress serves an API or web app but has no CORS configuration
    not annotations["nginx.ingress.kubernetes.io/enable-cors"]
    not annotations["nginx.ingress.kubernetes.io/cors-allow-origin"]

    # And appears to be an API based on path patterns
    some rule in input.review.object.spec.rules
    some path in rule.http.paths
    contains(path.path, "/api")

    msg := sprintf(
        "Info: Ingress '%s' appears to serve an API but has no CORS configuration. Consider configuring CORS headers if needed.",
        [input.review.object.metadata.name]
    )
}

# Deny Ingress with very permissive CORS
deny contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # CORS allows any origin
    annotations["nginx.ingress.kubernetes.io/cors-allow-origin"] == "*"

    msg := sprintf(
        "Ingress '%s' has CORS configured to allow any origin (*). Specify explicit allowed origins for security.",
        [input.review.object.metadata.name]
    )
}

# Warn about missing security headers
warn contains msg if {
    input.review.kind.kind == "Ingress"

    annotations := object.get(input.review.object.metadata, "annotations", {})

    # Check for common security headers
    not annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
    not annotations["nginx.ingress.kubernetes.io/server-snippet"]

    msg := sprintf(
        "Info: Ingress '%s' has no security headers configured. Consider adding headers like X-Frame-Options, X-Content-Type-Options, etc.",
        [input.review.object.metadata.name]
    )
}

# Deny Ingress pointing to ClusterIP service on insecure port
warn contains msg if {
    input.review.kind.kind == "Ingress"

    some rule in input.review.object.spec.rules
    some path in rule.http.paths

    # Backend service uses port 80 (HTTP) or other insecure ports
    backend_port := path.backend.service.port.number
    backend_port in {80, 8080, 8000}

    msg := sprintf(
        "Warning: Ingress '%s' routes to service '%s' on insecure port %d. Ensure backend service uses TLS or that the ingress controller handles TLS termination.",
        [input.review.object.metadata.name, path.backend.service.name, backend_port]
    )
}

# Deny Ingress with backend pointing to kube-system namespace
deny contains msg if {
    input.review.kind.kind == "Ingress"

    # Get ingress namespace
    ingress_namespace := object.get(input.review.object.metadata, "namespace", "default")

    # Check if any backend references kube-system (cross-namespace access)
    some rule in input.review.object.spec.rules
    some path in rule.http.paths

    # If service name contains namespace prefix pattern
    service_name := path.backend.service.name
    contains(service_name, "kube-system")

    msg := sprintf(
        "Ingress '%s' in namespace '%s' appears to reference system services. User ingress should not expose system services.",
        [input.review.object.metadata.name, ingress_namespace]
    )
}

# Warn about Ingress paths without pathType
warn contains msg if {
    input.review.kind.kind == "Ingress"

    some rule in input.review.object.spec.rules
    some path in rule.http.paths

    # pathType is not specified (deprecated in newer Kubernetes versions)
    not path.pathType

    msg := sprintf(
        "Warning: Ingress '%s' has path '%s' without pathType. Specify pathType (Prefix, Exact, or ImplementationSpecific) for compatibility.",
        [input.review.object.metadata.name, path.path]
    )
}

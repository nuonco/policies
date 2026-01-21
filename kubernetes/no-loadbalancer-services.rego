# No LoadBalancer Services Policy
#
# This policy prevents the creation of Kubernetes Services with type LoadBalancer,
# which can incur significant cloud provider costs and may bypass network security controls.
#
# Use Case:
# - Control cloud spending by preventing automatic load balancer provisioning
# - Enforce use of Ingress controllers or alternative load balancing solutions
# - Prevent accidental exposure of services via public load balancers
# - Standardize on specific networking patterns
#
# Policy Type: kubernetes_manifest
# Engine: opa
#
# Example violation:
# ```yaml
# apiVersion: v1
# kind: Service
# metadata:
#   name: my-service
# spec:
#   type: LoadBalancer  # ⛔ This will be denied
#   ports:
#     - port: 80
# ```

package nuon

import future.keywords.if
import future.keywords.in

# Deny Services with type LoadBalancer
deny contains msg if {
    # Check if this is a Service resource
    input.review.kind.kind == "Service"

    # Check if the service type is LoadBalancer
    input.review.object.spec.type == "LoadBalancer"

    msg := sprintf(
        "Service '%s' of type LoadBalancer is not allowed. Use an Ingress resource or NodePort service instead.",
        [input.review.object.metadata.name]
    )
}

# Warn about NodePort services (alternative that may also need review)
warn contains msg if {
    input.review.kind.kind == "Service"
    input.review.object.spec.type == "NodePort"

    msg := sprintf(
        "Warning: Service '%s' uses type NodePort. Consider using an Ingress controller for better security and management.",
        [input.review.object.metadata.name]
    )
}

# Provide helpful suggestion when ClusterIP is used (good practice)
# This is informational and doesn't block deployment
warn contains msg if {
    input.review.kind.kind == "Service"
    input.review.object.spec.type == "ClusterIP"

    # Check if there's no annotation indicating external access strategy
    not input.review.object.metadata.annotations["external-access"]

    msg := sprintf(
        "Info: Service '%s' uses ClusterIP (internal only). If external access is needed, consider adding an Ingress resource.",
        [input.review.object.metadata.name]
    )
}

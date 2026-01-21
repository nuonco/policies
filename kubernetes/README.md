# Kubernetes Manifest OPA Policy Examples

This directory contains example [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) policies for use with Nuon's policy enforcement system for Kubernetes manifest components.

## Overview

Nuon supports policy evaluation during the planning phase of Kubernetes manifest deployments. These policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), OPA's policy language, and can enforce security, compliance, resource management, and operational best practices.

## How Policies Work

1. **Trigger**: Policies are evaluated after Kubernetes manifests are rendered (via kubectl dry-run or template), before deployment
2. **Input**: Each policy receives Kubernetes manifests in AdmissionReview format
3. **Rules**: Policies define `deny` rules (block deployment) and `warn` rules (log warnings)
4. **Multiple Resources**: Each resource in a multi-document YAML is evaluated separately

### Input Format

Policies receive input in Kubernetes AdmissionReview format:

```json
{
  "review": {
    "kind": {
      "kind": "Service",
      "group": "",
      "version": "v1"
    },
    "object": {
      "apiVersion": "v1",
      "kind": "Service",
      "metadata": {
        "name": "my-service",
        "namespace": "default"
      },
      "spec": {
        "type": "LoadBalancer",
        "ports": [...]
      }
    }
  }
}
```

## Example Policies

### 1. No LoadBalancer Services (`no-loadbalancer-services.rego`)

**Purpose**: Prevent creation of Services with type LoadBalancer to control cloud costs and networking patterns.

**What it checks**:
- ⛔ **Denies**: Services with `type: LoadBalancer`
- ⚠️ **Warns**: Services with `type: NodePort`, suggests using Ingress controllers

**Use cases**:
- Control cloud spending (LoadBalancers incur significant costs)
- Enforce use of Ingress controllers for external access
- Standardize networking patterns

**Example violation**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: LoadBalancer  # ⛔ DENIED
  ports:
    - port: 80
```

**Example fix**:
```yaml
# Use ClusterIP with Ingress
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP  # ✅ ALLOWED
  ports:
    - port: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-service
                port:
                  number: 80
```

---

### 2. Container Security Context (`container-security-context.rego`)

**Purpose**: Enforce security best practices for container execution contexts.

**What it checks**:
- ⛔ **Denies**:
  - Containers running as root (missing `runAsNonRoot: true`)
  - Containers explicitly running as UID 0
  - Privileged containers
  - Containers with `allowPrivilegeEscalation != false`
  - Containers not dropping ALL capabilities
  - Host namespace usage (`hostNetwork`, `hostPID`, `hostIPC`)
- ⚠️ **Warns**:
  - Containers without read-only root filesystem
  - Containers adding Linux capabilities
  - Containers mounting host paths
  - Missing seccomp profiles

**Use cases**:
- Comply with Pod Security Standards (Restricted)
- Prevent privilege escalation vulnerabilities
- Follow CIS Kubernetes Benchmark
- Protect host systems from compromised containers

**Example violation**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: nginx:1.21
    # Missing securityContext ⛔ DENIED
```

**Example fix**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx:1.21
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

---

### 3. Resource Limits (`resource-limits.rego`)

**Purpose**: Ensure all containers have resource requests and limits defined.

**What it checks**:
- ⛔ **Denies**:
  - Containers without CPU requests
  - Containers without memory requests
  - Containers without CPU limits
  - Containers without memory limits
- ⚠️ **Warns**:
  - Very large resource limits (> 8 CPU, > 16Gi memory)
  - Limits much larger than requests (> 4x)
  - Very small resource requests (< 10m CPU, < 4Mi memory)

**Use cases**:
- Prevent resource starvation and noisy neighbor problems
- Enable proper pod scheduling
- Control costs by preventing runaway resource consumption
- Ensure predictable performance

**Example violation**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21
        # Missing resources ⛔ DENIED
```

**Example fix**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
          limits:
            cpu: "200m"
            memory: "256Mi"
```

---

### 4. Namespace Restrictions (`namespace-restrictions.rego`)

**Purpose**: Enforce proper namespace usage and protect system namespaces.

**What it checks**:
- ⛔ **Denies**:
  - Resources deployed to `default`, `kube-system`, `kube-public`, `kube-node-lease`
  - Resources deployed to namespaces with `kube-` prefix
  - Creation of Namespaces with reserved names
- ⚠️ **Warns**:
  - Resources without explicit namespace (will default to `default`)
  - Namespaces not following naming conventions
  - Namespaces without recommended labels

**Use cases**:
- Prevent accidental deployment to default namespace
- Protect system namespaces from user workloads
- Enforce organizational standards
- Support multi-tenancy

**Example violation**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: default  # ⛔ DENIED
spec:
  containers:
  - name: app
    image: nginx:1.21
```

**Example fix**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-application  # ✅ ALLOWED
spec:
  containers:
  - name: app
    image: nginx:1.21
```

---

### 5. Ingress Security (`ingress-security.rego`)

**Purpose**: Enforce HTTPS/TLS and security best practices for Ingress resources.

**What it checks**:
- ⛔ **Denies**:
  - Ingress without TLS configuration
  - Ingress explicitly allowing HTTP (`ssl-redirect: false`)
  - Ingress with weak TLS versions (TLS 1.0, 1.1)
  - Ingress with overly permissive CORS (`*` origin)
- ⚠️ **Warns**:
  - Ingress rules with hosts not covered by TLS
  - Missing SSL redirect annotation
  - Missing rate limiting
  - Missing authentication on non-public endpoints
  - Wildcard TLS certificates

**Use cases**:
- Enforce encryption in transit
- Comply with security frameworks requiring HTTPS
- Prevent insecure configurations
- Standardize ingress security patterns

**Example violation**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service
            port:
              number: 80
  # Missing tls section ⛔ DENIED
```

**Example fix**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - example.com
    secretName: example-tls
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service
            port:
              number: 80
```

---

### 6. Image Security (`image-security.rego`)

**Purpose**: Enforce security best practices for container images.

**What it checks**:
- ⛔ **Denies**:
  - Images using `:latest` tag
  - Images without explicit tag
  - Images from unapproved registries
  - Blocked/vulnerable images
  - Alpine Linux without specific version
- ⚠️ **Warns**:
  - Images not using digests (@sha256:...)
  - Public Docker Hub images
  - Old/EOL base images
  - Large base images
  - Missing image pull secrets for private registries

**Use cases**:
- Ensure reproducible deployments
- Enforce use of trusted registries
- Prevent known vulnerable images
- Improve supply chain security

**Example violation**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: app
    image: nginx:latest  # ⛔ DENIED - using 'latest'
```

**Example fix**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: app
    # Use specific version
    image: nginx:1.21.6
    # Or better: use digest for immutability
    # image: nginx@sha256:abc123...
```

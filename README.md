# Nuon OPA Policy Examples

This directory contains comprehensive example [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) policies for use with Nuon's policy enforcement system. These policies demonstrate best practices for enforcing security, compliance, cost management, and operational standards across your infrastructure deployments.

## Overview

Nuon's policy system evaluates infrastructure changes during the planning phase, before deployment. Policies can either block deployments (using `deny` rules) or provide warnings (using `warn` rules) based on your organization's requirements.

### How Policy Enforcement Works

1. **Planning Phase**: Nuon generates a plan for your component deployment (Terraform plan, Kubernetes manifests, or Helm templates)
2. **Policy Evaluation**: All applicable OPA policies are evaluated in parallel against the plan
3. **Result Aggregation**: Violations are collected and categorized as denials or warnings
4. **Enforcement**:
   - If any `deny` rules match → ❌ Deployment is blocked
   - If only `warn` rules match → ⚠️ Warnings are logged, deployment continues
   - If no violations → ✅ Deployment proceeds to approval/execution

## Policy Categories by Component Type

Nuon supports different input formats depending on the component type:

### 1. Terraform Module Policies

**Component Type**: `terraform_module`
**Input Format**: Terraform JSON plan (standard `terraform show -json` format)
**Location**: [`terraform/`](./terraform/)

Terraform policies receive the complete Terraform plan including resource changes, planned values, and configuration. This allows for sophisticated policies that can:
- Inspect resource configurations before and after changes
- Detect destructive operations
- Validate resource relationships
- Enforce organizational standards

**Available Examples**:
- [Security Group Ingress](./terraform/security-group-ingress.rego) - Prevent unrestricted internet access
- [Encryption at Rest](./terraform/encryption-at-rest.rego) - Enforce encryption for storage resources
- [Required Tags](./terraform/required-tags.rego) - Enforce tagging standards
- [Destructive Changes](./terraform/destructive-changes.rego) - Prevent accidental data loss
- [Cost Management](./terraform/cost-management.rego) - Control cloud spending
- [IAM Security](./terraform/iam-security.rego) - Enforce IAM best practices

[📖 See Terraform Policy Documentation](./terraform/README.md)

---

### 2. Kubernetes Manifest Policies

**Component Types**: `kubernetes_manifest` **AND** `helm_chart`
**Input Format**: Kubernetes AdmissionReview format
**Location**: [`kubernetes/`](./kubernetes/)

**Important**: Policies written for `kubernetes_manifest` components work identically with `helm_chart` components because both result in the same Kubernetes resource objects being evaluated. When Helm charts are templated, the resulting manifests are converted to AdmissionReview format just like raw Kubernetes manifests.

These policies receive Kubernetes resources in the same format used by Kubernetes admission webhooks, allowing you to:
- Enforce Pod Security Standards
- Validate resource configurations
- Ensure proper namespace usage
- Control container image sources
- Manage resource allocation

**Available Examples**:
- [No LoadBalancer Services](./kubernetes/no-loadbalancer-services.rego) - Control networking and costs
- [Container Security Context](./kubernetes/container-security-context.rego) - Enforce secure container configurations
- [Resource Limits](./kubernetes/resource-limits.rego) - Require resource requests and limits
- [Namespace Restrictions](./kubernetes/namespace-restrictions.rego) - Prevent deployment to system namespaces
- [Ingress Security](./kubernetes/ingress-security.rego) - Enforce HTTPS and TLS
- [Image Security](./kubernetes/image-security.rego) - Control container image sources and tags

[📖 See Kubernetes Policy Documentation](./kubernetes/README.md)

> **NOTE**: The policies for Kubernetes Manifests will work as is for Helm Chart component as well, as both of them result in the same input format (AccessReview Request objects) for the evaluation engine.

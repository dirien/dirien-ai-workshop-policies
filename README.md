# Pulumi Kubernetes Policy Pack

This repository contains a Pulumi Policy Pack that enforces Kubernetes best practices and security standards. The policies are written in TypeScript and validate Kubernetes resources before they are deployed.

## Policies

### 1. no-public-services (Mandatory)

**Enforcement Level:** `mandatory`

**Description:** Ensures that Kubernetes Services are cluster-private and not exposed to the public internet.

**What it checks:**
- Validates that Services do not use `type: LoadBalancer`

**Violation Example:**
```typescript
new k8s.core.v1.Service("public-service", {
    spec: {
        type: "LoadBalancer", // ❌ Violates policy
        // ...
    },
});
```

**Compliant Example:**
```typescript
new k8s.core.v1.Service("private-service", {
    spec: {
        type: "ClusterIP", // ✅ Compliant
        // ...
    },
});
```

---

### 2. disallow-capabilities (Advisory)

**Enforcement Level:** `advisory`

**Description:** Implements Pod Security Standards (Baseline) by restricting which Linux capabilities can be added to containers.

**What it checks:**
- Validates that containers only add capabilities from the allowed list
- Checks containers, initContainers, and ephemeralContainers
- Applies to: Pods, Deployments, StatefulSets, and Jobs

**Allowed Capabilities:**
- `AUDIT_WRITE`
- `CHOWN`
- `DAC_OVERRIDE`
- `FOWNER`
- `FSETID`
- `KILL`
- `MKNOD`
- `NET_BIND_SERVICE`
- `SETFCAP`
- `SETGID`
- `SETPCAP`
- `SETUID`
- `SYS_CHROOT`

**Violation Example:**
```typescript
new k8s.core.v1.Pod("pod", {
    spec: {
        containers: [{
            name: "app",
            image: "myapp:1.0.0",
            securityContext: {
                capabilities: {
                    add: ["NET_ADMIN", "SYS_ADMIN"], // ❌ Not in allowed list
                },
            },
        }],
    },
});
```

**Compliant Example:**
```typescript
new k8s.core.v1.Pod("pod", {
    spec: {
        containers: [{
            name: "app",
            image: "myapp:1.0.0",
            securityContext: {
                capabilities: {
                    add: ["NET_BIND_SERVICE"], // ✅ In allowed list
                },
            },
        }],
    },
});
```

---

### 3. disallow-latest-tag (Advisory)

**Enforcement Level:** `advisory`

**Description:** Ensures that container images use immutable tags instead of the mutable `:latest` tag or no tag at all.

**What it checks:**
- Validates that all container images include a tag (not using implicit `:latest`)
- Ensures the tag is not explicitly `:latest`
- Checks containers, initContainers, and ephemeralContainers
- Applies to: Pods, Deployments, StatefulSets, and Jobs

**Violation Examples:**
```typescript
// ❌ No tag specified (defaults to :latest)
new k8s.core.v1.Pod("pod", {
    spec: {
        containers: [{
            name: "app",
            image: "nginx", // ❌ Missing tag
        }],
    },
});

// ❌ Explicit :latest tag
new k8s.core.v1.Pod("pod", {
    spec: {
        containers: [{
            name: "app",
            image: "nginx:latest", // ❌ Mutable tag
        }],
    },
});
```

**Compliant Example:**
```typescript
new k8s.core.v1.Pod("pod", {
    spec: {
        containers: [{
            name: "app",
            image: "nginx:1.25.3", // ✅ Specific immutable tag
        }],
    },
});
```

---

### 4. require-oci-helm-charts (Mandatory)

**Enforcement Level:** `mandatory`

**Description:** Ensures that all Helm deployments use OCI-based charts for better security, provenance, and reproducibility. OCI registries enforce authentication and version immutability.

**What it checks:**
- Validates that Helm charts use `oci://` protocol
- Blocks charts fetched from HTTP/HTTPS repositories
- Blocks charts using `repositoryOpts.repo` with HTTP/HTTPS URLs
- Applies to: `kubernetes.helm.v3.Release` and `kubernetes.helm.v4.Chart`

**Violation Examples:**

```typescript
// ❌ Direct HTTP URL
new k8s.helm.v3.Release("nginx", {
    chart: "https://charts.bitnami.com/bitnami/nginx-1.2.3.tgz",
});

// ❌ Chart reference with HTTP repository
new k8s.helm.v3.Release("nginx", {
    chart: "nginx",
    repositoryOpts: {
        repo: "https://charts.bitnami.com/bitnami",
    },
});

// ❌ v4.Chart with HTTP repository
new k8s.helm.v4.Chart("nginx", {
    chart: "nginx",
    repositoryOpts: {
        repo: "https://kubernetes-charts.storage.googleapis.com",
    },
});
```

**Compliant Examples:**

```typescript
// ✅ OCI registry (v3.Release)
new k8s.helm.v3.Release("nginx", {
    chart: "oci://registry-1.docker.io/bitnamicharts/nginx",
    version: "15.0.0",
});

// ✅ OCI registry (v4.Chart)
new k8s.helm.v4.Chart("nginx", {
    chart: "oci://ghcr.io/myorg/nginx",
    version: "1.2.3",
});

// ✅ Local chart for development
new k8s.helm.v3.Release("nginx", {
    chart: "./charts/nginx",
});
```

---

## Resource Coverage

The policies validate the following Kubernetes resources:

| Policy | Pod | Deployment | StatefulSet | Job | Service | Helm v3 | Helm v4 |
|--------|-----|------------|-------------|-----|---------|---------|---------|
| no-public-services | - | - | - | - | ✅ | - | - |
| disallow-capabilities | ✅ | ✅ | ✅ | ✅ | - | - | - |
| disallow-latest-tag | ✅ | ✅ | ✅ | ✅ | - | - | - |
| require-oci-helm-charts | - | - | - | - | - | ✅ | ✅ |

---

## Usage

### Install Dependencies

```bash
npm install
```

### Enable the Policy Pack

You can enable this policy pack in several ways:

#### 1. Local Development (Policy Pack as Code)

```bash
pulumi preview --policy-pack .
pulumi up --policy-pack .
```

#### 2. Organization-Level Enforcement

Publish the policy pack to your Pulumi organization:

```bash
pulumi policy publish
```

Then enable it in the Pulumi Console for your organization or specific stacks.

### Testing with Example Violations

The repository includes `example-violations.ts` with examples of resources that violate the policies. You can test the policies by running:

```bash
pulumi preview --policy-pack . example-violations.ts
```

---

## Enforcement Levels

- **mandatory**: Policy violations will block the deployment (`pulumi up` will fail)
- **advisory**: Policy violations will be reported but won't block deployment

---

## Policy Mapping from Kyverno

These policies are based on Kyverno Kubernetes policies:

1. **disallow-capabilities** ← Kyverno: `disallow-capabilities` (Pod Security Standards - Baseline)
2. **disallow-latest-tag** ← Kyverno: `disallow-latest-tag` (Best Practices)

---

## File Structure

```
.
├── index.ts                 # Policy Pack definitions
├── example-violations.ts    # Example resources that violate policies
├── package.json            # Node.js dependencies
├── tsconfig.json           # TypeScript configuration
├── PulumiPolicy.yaml       # Policy Pack metadata
└── README.md              # This file
```

---

## Customization

### Changing Enforcement Levels

Edit `index.ts` and modify the `enforcementLevel` property:

```typescript
{
    name: "no-public-services",
    enforcementLevel: "advisory", // Change to "advisory" or "mandatory"
    // ...
}
```

### Modifying Allowed Capabilities

Edit the `allowedCapabilities` array in the `checkCapabilities` helper function in `index.ts`:

```typescript
const allowedCapabilities = [
    "AUDIT_WRITE",
    "CHOWN",
    // Add or remove capabilities as needed
];
```

---

## Contributing

To add new policies:

1. Add the policy definition to the `policies` array in `index.ts`
2. Create example violations in `example-violations.ts`
3. Update this README with policy documentation
4. Test with `pulumi preview --policy-pack .`

---

## References

- [Pulumi Policy as Code](https://www.pulumi.com/docs/using-pulumi/crossguard/)
- [Kyverno Policies](https://kyverno.io/policies/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

import * as aws from "@pulumi/aws";
import * as k8s from "@pulumi/kubernetes";

// ============================================
// AWS EC2 EXAMPLES
// ============================================

// This EC2 instance violates disallow-gpu-instance-types policy (g-family)
const gpuInstanceG4dn = new aws.ec2.Instance("gpu-instance-g4dn", {
    instanceType: "g4dn.xlarge", // Violates: GPU instance type
    ami: "ami-0c55b159cbfafe1f0",
    tags: {
        Name: "ml-training-instance",
        Purpose: "machine-learning",
    },
});

// This EC2 instance violates disallow-gpu-instance-types policy (p-family)
const gpuInstanceP3 = new aws.ec2.Instance("gpu-instance-p3", {
    instanceType: "p3.2xlarge", // Violates: GPU instance type
    ami: "ami-0c55b159cbfafe1f0",
    tags: {
        Name: "deep-learning-instance",
        Purpose: "ai-training",
    },
});

// This EC2 instance violates disallow-gpu-instance-types policy (g5-family)
const gpuInstanceG5 = new aws.ec2.Instance("gpu-instance-g5", {
    instanceType: "g5.xlarge", // Violates: GPU instance type
    ami: "ami-0c55b159cbfafe1f0",
    tags: {
        Name: "graphics-workstation",
        Purpose: "rendering",
    },
});

// This EC2 instance violates disallow-gpu-instance-types policy (p4-family)
const gpuInstanceP4 = new aws.ec2.Instance("gpu-instance-p4", {
    instanceType: "p4d.24xlarge", // Violates: GPU instance type
    ami: "ami-0c55b159cbfafe1f0",
    tags: {
        Name: "hpc-cluster-node",
        Purpose: "high-performance-compute",
    },
});

// ============================================
// POD EXAMPLES
// ============================================

// This Pod violates MULTIPLE policies:
// - disallow-capabilities: adds NET_ADMIN and SYS_TIME
// - disallow-latest-tag: uses :latest tag
const podWithDisallowedCapability = new k8s.core.v1.Pod("bad-capability-pod", {
    metadata: {
        name: "pod-with-net-admin",
    },
    spec: {
        containers: [{
            name: "nginx",
            image: "nginx:latest", // Violates disallow-latest-tag
            securityContext: {
                capabilities: {
                    add: ["NET_ADMIN", "SYS_TIME"], // Violates disallow-capabilities
                },
            },
        }],
    },
});

// This Pod violates disallow-latest-tag by using image without tag
const podWithoutTag = new k8s.core.v1.Pod("pod-without-tag", {
    metadata: {
        name: "pod-no-tag",
    },
    spec: {
        containers: [{
            name: "app",
            image: "nginx", // Violates: no tag specified
        }],
    },
});

// This Pod violates disallow-capabilities in initContainers
const podWithInitContainerViolation = new k8s.core.v1.Pod("init-violation-pod", {
    metadata: {
        name: "pod-with-init-violation",
    },
    spec: {
        initContainers: [{
            name: "init",
            image: "busybox:latest", // Violates disallow-latest-tag
            securityContext: {
                capabilities: {
                    add: ["SYS_ADMIN"], // Violates disallow-capabilities
                },
            },
        }],
        containers: [{
            name: "app",
            image: "nginx", // Violates: no tag
        }],
    },
});

// ============================================
// DEPLOYMENT EXAMPLES
// ============================================

// This Deployment violates disallow-latest-tag policy
const deploymentWithLatestTag = new k8s.apps.v1.Deployment("deployment-latest", {
    metadata: {
        name: "nginx-deployment-latest",
    },
    spec: {
        replicas: 3,
        selector: {
            matchLabels: {
                app: "nginx",
            },
        },
        template: {
            metadata: {
                labels: {
                    app: "nginx",
                },
            },
            spec: {
                containers: [{
                    name: "nginx",
                    image: "nginx:latest", // Violates disallow-latest-tag
                    ports: [{
                        containerPort: 80,
                    }],
                }],
            },
        },
    },
});

// This Deployment violates disallow-capabilities policy
const deploymentWithBadCapabilities = new k8s.apps.v1.Deployment("deployment-bad-caps", {
    metadata: {
        name: "app-with-admin",
    },
    spec: {
        replicas: 2,
        selector: {
            matchLabels: {
                app: "privileged-app",
            },
        },
        template: {
            metadata: {
                labels: {
                    app: "privileged-app",
                },
            },
            spec: {
                containers: [{
                    name: "app",
                    image: "myapp:1.0.0",
                    securityContext: {
                        capabilities: {
                            add: ["SYS_ADMIN", "NET_ADMIN"], // Violates disallow-capabilities
                        },
                    },
                }],
            },
        },
    },
});

// ============================================
// STATEFULSET EXAMPLES
// ============================================

// This StatefulSet violates both policies
const statefulSetViolations = new k8s.apps.v1.StatefulSet("statefulset-violations", {
    metadata: {
        name: "redis-cluster",
    },
    spec: {
        serviceName: "redis",
        replicas: 3,
        selector: {
            matchLabels: {
                app: "redis",
            },
        },
        template: {
            metadata: {
                labels: {
                    app: "redis",
                },
            },
            spec: {
                containers: [{
                    name: "redis",
                    image: "redis", // Violates: no tag specified
                    ports: [{
                        containerPort: 6379,
                    }],
                    securityContext: {
                        capabilities: {
                            add: ["SYS_RESOURCE", "IPC_LOCK"], // Violates disallow-capabilities
                        },
                    },
                }],
            },
        },
    },
});

// ============================================
// JOB EXAMPLES
// ============================================

// This Job violates disallow-latest-tag
const jobWithLatest = new k8s.batch.v1.Job("job-latest", {
    metadata: {
        name: "batch-job-latest",
    },
    spec: {
        template: {
            spec: {
                containers: [{
                    name: "processor",
                    image: "python:latest", // Violates disallow-latest-tag
                    command: ["python", "process.py"],
                }],
                restartPolicy: "Never",
            },
        },
    },
});

// This Job violates disallow-capabilities
const jobWithBadCapabilities = new k8s.batch.v1.Job("job-bad-caps", {
    metadata: {
        name: "privileged-job",
    },
    spec: {
        template: {
            spec: {
                initContainers: [{
                    name: "setup",
                    image: "busybox:1.36", // OK: has specific tag
                    command: ["sh", "-c", "echo setup"],
                    securityContext: {
                        capabilities: {
                            add: ["SYS_ADMIN", "SYS_PTRACE"], // Violates disallow-capabilities
                        },
                    },
                }],
                containers: [{
                    name: "worker",
                    image: "alpine", // Violates: no tag
                    command: ["sh", "-c", "echo processing"],
                }],
                restartPolicy: "OnFailure",
            },
        },
    },
});

// ============================================
// SERVICE EXAMPLES
// ============================================

// This Service violates the no-public-services policy
const publicService = new k8s.core.v1.Service("public-service", {
    metadata: {
        name: "public-lb-service",
    },
    spec: {
        type: "LoadBalancer", // Violates no-public-services
        ports: [{
            port: 80,
            targetPort: 8080,
        }],
        selector: {
            app: "myapp",
        },
    },
});

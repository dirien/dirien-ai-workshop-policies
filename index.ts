import * as aws from "@pulumi/aws";
import * as k8s from "@pulumi/kubernetes";
import {PolicyPack, validateResourceOfType} from "@pulumi/policy";

// Helper function to check container capabilities
const checkCapabilities = (containers: any[] | undefined, reportViolation: (message: string) => void) => {
    const allowedCapabilities = [
        "AUDIT_WRITE",
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "KILL",
        "MKNOD",
        "NET_BIND_SERVICE",
        "SETFCAP",
        "SETGID",
        "SETPCAP",
        "SETUID",
        "SYS_CHROOT",
    ];

    if (!containers) return;

    for (const container of containers) {
        const addedCapabilities = container.securityContext?.capabilities?.add;
        if (addedCapabilities) {
            for (const cap of addedCapabilities) {
                if (!allowedCapabilities.includes(cap)) {
                    reportViolation(
                        `Container '${container.name}' adds capability '${cap}' which is not in the allowed list. ` +
                        `Only the following capabilities are allowed: ${allowedCapabilities.join(", ")}.`
                    );
                }
            }
        }
    }
};

// Helper function to check image tags
const checkImageTags = (containers: any[] | undefined, reportViolation: (message: string) => void) => {
    if (!containers) return;

    for (const container of containers) {
        const image = container.image;
        if (!image) continue;

        // Check if image has a tag
        if (!image.includes(':')) {
            reportViolation(
                `Container '${container.name}' uses image '${image}' without a tag. An image tag is required.`
            );
        }
        // Check if image uses :latest tag
        else if (image.endsWith(':latest')) {
            reportViolation(
                `Container '${container.name}' uses image '${image}' with mutable ':latest' tag. Using a mutable image tag is not allowed.`
            );
        }
    }
};

new PolicyPack("acme-compliance-policies", {
    policies: [
        {
            name: "disallow-gpu-instance-types",
            description: "Disallow GPU and high-performance EC2 instance types (g*, p*) to prevent accidental costly provisioning.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.Instance, (instance, args, reportViolation) => {
                const instanceType = instance.instanceType;
                if (!instanceType) {
                    return;
                }

                // List of disallowed instance type prefixes
                // These can be easily extended to include other families
                const disallowedPrefixes = ["g", "p"];

                // Check if the instance type starts with any disallowed prefix
                for (const prefix of disallowedPrefixes) {
                    if (instanceType.startsWith(prefix)) {
                        reportViolation(
                            `GPU and high-performance instance types (g*, p*) are not permitted by organization policy. ` +
                            `Instance type '${instanceType}' is not allowed. Please use general-purpose instance types ` +
                            `(t3, t4g, m5, m6i, etc.) unless you have explicit approval for GPU workloads.`
                        );
                        return;
                    }
                }
            }),
            remediationSteps: "Change the instance type to a general-purpose instance family (t3, t4g, m5, m6i, c5, c6i, r5, r6i, etc.). " +
                "If GPU instances are required for ML or specialized compute workloads, request an exception from your platform team.",
        },
        {
            name: "no-public-services",
            description: "Kubernetes Services should be cluster-private.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(k8s.core.v1.Service, (svc, args, reportViolation) => {
                if (svc.spec && svc.spec.type === "LoadBalancer") {
                    reportViolation("Kubernetes Services cannot be of type LoadBalancer, which are exposed to " +
                        "anything that can reach the Kubernetes cluster. This likely including the " +
                        "public Internet.");
                }
            }),
            remediationSteps: "Change the Service type to ClusterIP or NodePort to restrict access within the cluster.",
        },
        {
            name: "disallow-capabilities",
            description: "Disallow Capabilities - Adding capabilities beyond the allowed list must be disallowed (Pod Security Standards Baseline).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.core.v1.Pod, (pod, args, reportViolation) => {
                if (pod.spec) {
                    checkCapabilities(pod.spec.containers, reportViolation);
                    checkCapabilities(pod.spec.initContainers, reportViolation);
                    checkCapabilities(pod.spec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Remove any added capabilities from the container security context that are not in the allowed list.",
        },
        {
            name: "disallow-capabilities-deployment",
            description: "Disallow Capabilities in Deployments - Adding capabilities beyond the allowed list must be disallowed (Pod Security Standards Baseline).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.apps.v1.Deployment, (deployment, args, reportViolation) => {
                const podSpec = deployment.spec?.template?.spec;
                if (podSpec) {
                    checkCapabilities(podSpec.containers, reportViolation);
                    checkCapabilities(podSpec.initContainers, reportViolation);
                    checkCapabilities(podSpec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Remove any added capabilities from the container security context that are not in the allowed list.",
        },
        {
            name: "disallow-capabilities-statefulset",
            description: "Disallow Capabilities in StatefulSets - Adding capabilities beyond the allowed list must be disallowed (Pod Security Standards Baseline).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.apps.v1.StatefulSet, (statefulset, args, reportViolation) => {
                const podSpec = statefulset.spec?.template?.spec;
                if (podSpec) {
                    checkCapabilities(podSpec.containers, reportViolation);
                    checkCapabilities(podSpec.initContainers, reportViolation);
                    checkCapabilities(podSpec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Remove any added capabilities from the container security context that are not in the allowed list.",
        },
        {
            name: "disallow-capabilities-job",
            description: "Disallow Capabilities in Jobs - Adding capabilities beyond the allowed list must be disallowed (Pod Security Standards Baseline).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.batch.v1.Job, (job, args, reportViolation) => {
                const podSpec = job.spec?.template?.spec;
                if (podSpec) {
                    checkCapabilities(podSpec.containers, reportViolation);
                    checkCapabilities(podSpec.initContainers, reportViolation);
                    checkCapabilities(podSpec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Remove any added capabilities from the container security context that are not in the allowed list.",
        },
        {
            name: "disallow-latest-tag",
            description: "Disallow Latest Tag - The ':latest' tag is mutable and can lead to unexpected errors. Use an immutable tag instead.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.core.v1.Pod, (pod, args, reportViolation) => {
                if (pod.spec) {
                    checkImageTags(pod.spec.containers, reportViolation);
                    checkImageTags(pod.spec.initContainers, reportViolation);
                    checkImageTags(pod.spec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Specify an immutable image tag instead of using the ':latest' tag.",
        },
        {
            name: "disallow-latest-tag-deployment",
            description: "Disallow Latest Tag in Deployments - The ':latest' tag is mutable and can lead to unexpected errors. Use an immutable tag instead.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.apps.v1.Deployment, (deployment, args, reportViolation) => {
                const podSpec = deployment.spec?.template?.spec;
                if (podSpec) {
                    checkImageTags(podSpec.containers, reportViolation);
                    checkImageTags(podSpec.initContainers, reportViolation);
                    checkImageTags(podSpec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Specify an immutable image tag instead of using the ':latest' tag.",
        },
        {
            name: "disallow-latest-tag-statefulset",
            description: "Disallow Latest Tag in StatefulSets - The ':latest' tag is mutable and can lead to unexpected errors. Use an immutable tag instead.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.apps.v1.StatefulSet, (statefulset, args, reportViolation) => {
                const podSpec = statefulset.spec?.template?.spec;
                if (podSpec) {
                    checkImageTags(podSpec.containers, reportViolation);
                    checkImageTags(podSpec.initContainers, reportViolation);
                    checkImageTags(podSpec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Specify an immutable image tag instead of using the ':latest' tag.",
        },
        {
            name: "disallow-latest-tag-job",
            description: "Disallow Latest Tag in Jobs - The ':latest' tag is mutable and can lead to unexpected errors. Use an immutable tag instead.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(k8s.batch.v1.Job, (job, args, reportViolation) => {
                const podSpec = job.spec?.template?.spec;
                if (podSpec) {
                    checkImageTags(podSpec.containers, reportViolation);
                    checkImageTags(podSpec.initContainers, reportViolation);
                    checkImageTags(podSpec.ephemeralContainers, reportViolation);
                }
            }),
            remediationSteps: "Specify an immutable image tag instead of using the ':latest' tag.",
        },
    ],
});

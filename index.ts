import * as k8s from "@pulumi/kubernetes";
import { PolicyPack, validateResourceOfType, ResourceValidationPolicy } from "@pulumi/policy";

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

new PolicyPack("kubernetes-typescript", {
    policies: [
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
        },
        {
            name: "helm-v3-require-oci-registry",
            description: "Helm v3 Release - Require OCI-based registries. Traditional Helm repositories (HTTPS URLs) are not allowed.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(k8s.helm.v3.Release, (release, args, reportViolation) => {
                const repo = release.repositoryOpts?.repo;
                
                // If repositoryOpts.repo is specified, it must use OCI protocol
                if (repo) {
                    if (!repo.startsWith("oci://")) {
                        reportViolation(
                            `Helm v3 Release '${args.name}' uses non-OCI repository '${repo}'. ` +
                            `Only OCI-based registries (oci://) are allowed. Traditional Helm repositories are not permitted.`
                        );
                    }
                }
            }),
        },
        {
            name: "helm-v4-require-oci-registry",
            description: "Helm v4 Chart - Require OCI-based registries. Traditional Helm repositories and HTTPS chart URLs are not allowed.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(k8s.helm.v4.Chart, (chart, args, reportViolation) => {
                const repo = chart.repositoryOpts?.repo;
                const chartRef = chart.chart;
                
                // Disallow repositoryOpts.repo entirely for v4 (should use OCI in chart property)
                if (repo) {
                    reportViolation(
                        `Helm v4 Chart '${args.name}' uses repositoryOpts.repo '${repo}'. ` +
                        `For v4 Charts, use OCI registry URLs directly in the 'chart' property (e.g., oci://registry.example.com/charts/mychart).`
                    );
                }
                
                // Ensure chart property uses OCI protocol
                if (chartRef) {
                    // Check for HTTPS URLs (direct chart downloads)
                    if (chartRef.startsWith("http://") || chartRef.startsWith("https://")) {
                        reportViolation(
                            `Helm v4 Chart '${args.name}' uses HTTPS URL '${chartRef}'. ` +
                            `Only OCI-based registries (oci://) are allowed.`
                        );
                    }
                    // Check for repo/chart references (requires traditional Helm repo setup)
                    else if (chartRef.includes("/") && !chartRef.startsWith("oci://") && !chartRef.startsWith("./") && !chartRef.startsWith("../")) {
                        reportViolation(
                            `Helm v4 Chart '${args.name}' uses repository reference '${chartRef}'. ` +
                            `Only OCI-based registries (oci://) are allowed. Use format: oci://registry.example.com/charts/mychart`
                        );
                    }
                    // Ensure OCI protocol is used for remote charts
                    else if (!chartRef.startsWith("oci://") && !chartRef.startsWith("./") && !chartRef.startsWith("../")) {
                        reportViolation(
                            `Helm v4 Chart '${args.name}' uses chart reference '${chartRef}' without OCI protocol. ` +
                            `Only OCI-based registries (oci://) are allowed.`
                        );
                    }
                }
            }),
        },
    ],
});

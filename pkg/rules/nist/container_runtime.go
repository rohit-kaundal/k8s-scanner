package nist

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type ContainerRuntimeRule struct{}

func NewContainerRuntimeRule() *ContainerRuntimeRule {
	return &ContainerRuntimeRule{}
}

func (r *ContainerRuntimeRule) ID() string {
	return "NIST-4.2.1"
}

func (r *ContainerRuntimeRule) Title() string {
	return "Container runtime security"
}

func (r *ContainerRuntimeRule) Description() string {
	return "Containers should run with non-root user and read-only root filesystem"
}

func (r *ContainerRuntimeRule) Standard() string {
	return "nist"
}

func (r *ContainerRuntimeRule) Section() string {
	return "4.2.1"
}

func (r *ContainerRuntimeRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *ContainerRuntimeRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
	k8sClient, ok := client.(*k8s.Client)
	if !ok {
		return nil, fmt.Errorf("expected k8s client")
	}

	var findings []types.Finding

	pods, err := k8sClient.GetPods(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get pods: %w", err)
	}

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext == nil {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' has no security context", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusFailed,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Add security context with runAsNonRoot: true and readOnlyRootFilesystem: true",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
					},
				}
				findings = append(findings, finding)
				continue
			}

			sc := container.SecurityContext
			if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' may run as root", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusFailed,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Set runAsNonRoot: true in security context",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
					},
				}
				findings = append(findings, finding)
			}

			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' has writable root filesystem", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Set readOnlyRootFilesystem: true in security context",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "All containers have secure runtime configuration",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue using secure runtime configurations",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
			},
		})
	}

	return findings, nil
}
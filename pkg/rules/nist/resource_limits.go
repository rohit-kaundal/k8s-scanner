package nist

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type ResourceLimitsRule struct{}

func NewResourceLimitsRule() *ResourceLimitsRule {
	return &ResourceLimitsRule{}
}

func (r *ResourceLimitsRule) ID() string {
	return "NIST-4.4.1"
}

func (r *ResourceLimitsRule) Title() string {
	return "Resource limits and quotas"
}

func (r *ResourceLimitsRule) Description() string {
	return "Containers should have CPU and memory limits to prevent resource exhaustion"
}

func (r *ResourceLimitsRule) Standard() string {
	return "nist"
}

func (r *ResourceLimitsRule) Section() string {
	return "4.4.1"
}

func (r *ResourceLimitsRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *ResourceLimitsRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
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
			if container.Resources.Limits == nil {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' has no resource limits", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Set CPU and memory limits in container resources",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
					},
				}
				findings = append(findings, finding)
				continue
			}

			limits := container.Resources.Limits
			if limits.Cpu().IsZero() {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' has no CPU limits", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Set CPU limits in container resources",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
					},
				}
				findings = append(findings, finding)
			}

			if limits.Memory().IsZero() {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' has no memory limits", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Set memory limits in container resources",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
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
			Description: "All containers have proper resource limits",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue setting resource limits",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			},
		})
	}

	return findings, nil
}
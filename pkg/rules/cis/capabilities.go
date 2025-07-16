package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type CapabilitiesRule struct{}

func NewCapabilitiesRule() *CapabilitiesRule {
	return &CapabilitiesRule{}
}

func (r *CapabilitiesRule) ID() string {
	return "CIS-5.1.4"
}

func (r *CapabilitiesRule) Title() string {
	return "Minimize the admission of containers with capabilities"
}

func (r *CapabilitiesRule) Description() string {
	return "Containers should drop all capabilities and only add specific ones that are required"
}

func (r *CapabilitiesRule) Standard() string {
	return "cis"
}

func (r *CapabilitiesRule) Section() string {
	return "5.1.4"
}

func (r *CapabilitiesRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *CapabilitiesRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
	k8sClient, ok := client.(*k8s.Client)
	if !ok {
		return nil, fmt.Errorf("expected k8s client")
	}

	var findings []types.Finding

	pods, err := k8sClient.GetPods(ctx, config.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get pods: %w", err)
	}

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' does not specify capabilities", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Drop all capabilities and only add required ones: drop: [ALL], add: [REQUIRED_CAPS]",
					References: []string{
						"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
						"https://www.cisecurity.org/benchmark/kubernetes",
					},
				}
				findings = append(findings, finding)
			} else {
				caps := container.SecurityContext.Capabilities
				if caps.Drop == nil || len(caps.Drop) == 0 {
					finding := types.Finding{
						ID:          r.ID(),
						Title:       r.Title(),
						Description: fmt.Sprintf("Container '%s' does not drop capabilities", container.Name),
						Standard:    r.Standard(),
						Section:     r.Section(),
						Severity:    r.Severity(),
						Status:      types.StatusFailed,
						Resource: types.Resource{
							Kind:      "Pod",
							Name:      pod.Name,
							Namespace: pod.Namespace,
						},
						Remediation: "Add drop: [ALL] to capabilities and only add required ones",
						References: []string{
							"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
							"https://www.cisecurity.org/benchmark/kubernetes",
						},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "All containers properly manage capabilities",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to properly manage container capabilities",
			References: []string{
				"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
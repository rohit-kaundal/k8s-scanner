package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type RootFilesystemRule struct{}

func NewRootFilesystemRule() *RootFilesystemRule {
	return &RootFilesystemRule{}
}

func (r *RootFilesystemRule) ID() string {
	return "CIS-5.1.3"
}

func (r *RootFilesystemRule) Title() string {
	return "Minimize the admission of containers with allowPrivilegeEscalation"
}

func (r *RootFilesystemRule) Description() string {
	return "Containers should not allow privilege escalation to prevent gaining additional privileges"
}

func (r *RootFilesystemRule) Standard() string {
	return "cis"
}

func (r *RootFilesystemRule) Section() string {
	return "5.1.3"
}

func (r *RootFilesystemRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *RootFilesystemRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
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
			if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' allows privilege escalation", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusFailed,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Set allowPrivilegeEscalation: false in container security context",
					References: []string{
						"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
						"https://www.cisecurity.org/benchmark/kubernetes",
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
			Description: "All containers properly restrict privilege escalation",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to set allowPrivilegeEscalation: false",
			References: []string{
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
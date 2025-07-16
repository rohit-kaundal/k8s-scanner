package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type PrivilegedContainerRule struct{}

func NewPrivilegedContainerRule() *PrivilegedContainerRule {
	return &PrivilegedContainerRule{}
}

func (r *PrivilegedContainerRule) ID() string {
	return "CIS-5.1.2"
}

func (r *PrivilegedContainerRule) Title() string {
	return "Minimize the admission of privileged containers"
}

func (r *PrivilegedContainerRule) Description() string {
	return "Privileged containers should not be used as they have access to all Linux kernel capabilities and devices"
}

func (r *PrivilegedContainerRule) Standard() string {
	return "cis"
}

func (r *PrivilegedContainerRule) Section() string {
	return "5.1.2"
}

func (r *PrivilegedContainerRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *PrivilegedContainerRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' is running in privileged mode", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusFailed,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Remove privileged: true from container security context or use specific capabilities instead",
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
			Description: "No privileged containers found",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to avoid privileged containers",
			References: []string{
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type SeccompProfileRule struct{}

func NewSeccompProfileRule() *SeccompProfileRule {
	return &SeccompProfileRule{}
}

func (r *SeccompProfileRule) ID() string {
	return "CIS-5.1.8"
}

func (r *SeccompProfileRule) Title() string {
	return "Minimize the admission of containers with seccomp profile"
}

func (r *SeccompProfileRule) Description() string {
	return "Containers should have a seccomp profile applied to restrict system calls"
}

func (r *SeccompProfileRule) Standard() string {
	return "cis"
}

func (r *SeccompProfileRule) Section() string {
	return "5.1.8"
}

func (r *SeccompProfileRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *SeccompProfileRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
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
			hasSeccomp := false
			
			if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
				hasSeccomp = true
			}
			
			if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
				hasSeccomp = true
			}

			if !hasSeccomp {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' does not have a seccomp profile", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Add seccompProfile with type: RuntimeDefault or custom profile",
					References: []string{
						"https://kubernetes.io/docs/tutorials/security/seccomp/",
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
			Description: "All containers have seccomp profiles configured",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to use seccomp profiles",
			References: []string{
				"https://kubernetes.io/docs/tutorials/security/seccomp/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
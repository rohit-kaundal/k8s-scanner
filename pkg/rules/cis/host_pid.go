package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type HostPIDRule struct{}

func NewHostPIDRule() *HostPIDRule {
	return &HostPIDRule{}
}

func (r *HostPIDRule) ID() string {
	return "CIS-5.1.6"
}

func (r *HostPIDRule) Title() string {
	return "Minimize the admission of containers with hostPID"
}

func (r *HostPIDRule) Description() string {
	return "Containers should not use the host PID namespace as it gives access to host processes"
}

func (r *HostPIDRule) Standard() string {
	return "cis"
}

func (r *HostPIDRule) Section() string {
	return "5.1.6"
}

func (r *HostPIDRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *HostPIDRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
		if pod.Spec.HostPID {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: "Pod is using host PID namespace",
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusFailed,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Set hostPID: false or remove the hostPID field",
				References: []string{
					"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
					"https://www.cisecurity.org/benchmark/kubernetes",
				},
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "No pods using host PID namespace found",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to avoid using host PID namespace",
			References: []string{
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type HostNetworkRule struct{}

func NewHostNetworkRule() *HostNetworkRule {
	return &HostNetworkRule{}
}

func (r *HostNetworkRule) ID() string {
	return "CIS-5.1.5"
}

func (r *HostNetworkRule) Title() string {
	return "Minimize the admission of containers with hostNetwork"
}

func (r *HostNetworkRule) Description() string {
	return "Containers should not use the host network as it gives access to the host's network interfaces"
}

func (r *HostNetworkRule) Standard() string {
	return "cis"
}

func (r *HostNetworkRule) Section() string {
	return "5.1.5"
}

func (r *HostNetworkRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *HostNetworkRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
		if pod.Spec.HostNetwork {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: "Pod is using host network",
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusFailed,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Set hostNetwork: false or remove the hostNetwork field",
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
			Description: "No pods using host network found",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to avoid using host network",
			References: []string{
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
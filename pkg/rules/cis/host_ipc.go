package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type HostIPCRule struct{}

func NewHostIPCRule() *HostIPCRule {
	return &HostIPCRule{}
}

func (r *HostIPCRule) ID() string {
	return "CIS-5.1.7"
}

func (r *HostIPCRule) Title() string {
	return "Minimize the admission of containers with hostIPC"
}

func (r *HostIPCRule) Description() string {
	return "Containers should not use the host IPC namespace as it gives access to host inter-process communication"
}

func (r *HostIPCRule) Standard() string {
	return "cis"
}

func (r *HostIPCRule) Section() string {
	return "5.1.7"
}

func (r *HostIPCRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *HostIPCRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
		if pod.Spec.HostIPC {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: "Pod is using host IPC namespace",
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusFailed,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Set hostIPC: false or remove the hostIPC field",
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
			Description: "No pods using host IPC namespace found",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to avoid using host IPC namespace",
			References: []string{
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
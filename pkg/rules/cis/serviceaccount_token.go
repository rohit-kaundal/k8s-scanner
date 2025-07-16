package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type ServiceAccountTokenRule struct{}

func NewServiceAccountTokenRule() *ServiceAccountTokenRule {
	return &ServiceAccountTokenRule{}
}

func (r *ServiceAccountTokenRule) ID() string {
	return "CIS-5.1.10"
}

func (r *ServiceAccountTokenRule) Title() string {
	return "Minimize the admission of containers with service account tokens"
}

func (r *ServiceAccountTokenRule) Description() string {
	return "Containers should not automatically mount service account tokens unless required"
}

func (r *ServiceAccountTokenRule) Standard() string {
	return "cis"
}

func (r *ServiceAccountTokenRule) Section() string {
	return "5.1.10"
}

func (r *ServiceAccountTokenRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *ServiceAccountTokenRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
		autoMountToken := true
		
		if pod.Spec.AutomountServiceAccountToken != nil {
			autoMountToken = *pod.Spec.AutomountServiceAccountToken
		}
		
		if autoMountToken {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: "Pod automatically mounts service account token",
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Set automountServiceAccountToken: false unless token is required",
				References: []string{
					"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
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
			Description: "All pods properly manage service account token mounting",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to disable automatic service account token mounting",
			References: []string{
				"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
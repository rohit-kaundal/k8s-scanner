package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type PodSecurityContextRule struct{}

func NewPodSecurityContextRule() *PodSecurityContextRule {
	return &PodSecurityContextRule{}
}

func (r *PodSecurityContextRule) ID() string {
	return "CIS-5.1.1"
}

func (r *PodSecurityContextRule) Title() string {
	return "Ensure that the cluster-admin role is only used where required"
}

func (r *PodSecurityContextRule) Description() string {
	return "The cluster-admin role should only be used where required as it gives unrestricted access to the cluster"
}

func (r *PodSecurityContextRule) Standard() string {
	return "cis"
}

func (r *PodSecurityContextRule) Section() string {
	return "5.1.1"
}

func (r *PodSecurityContextRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *PodSecurityContextRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
	k8sClient, ok := client.(*k8s.Client)
	if !ok {
		return nil, fmt.Errorf("expected k8s client")
	}

	var findings []types.Finding

	clusterRoleBindings, err := k8sClient.GetClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster role bindings: %w", err)
	}

	for _, binding := range clusterRoleBindings.Items {
		if binding.RoleRef.Name == "cluster-admin" {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: r.Description(),
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "ClusterRoleBinding",
					Name:      binding.Name,
					Namespace: binding.Namespace,
				},
				Remediation: "Review the necessity of cluster-admin role binding and consider using more restrictive roles",
				References: []string{
					"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
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
			Description: "No cluster-admin role bindings found",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "ClusterRoleBinding",
				Name: "all",
			},
			Remediation: "Continue to avoid unnecessary cluster-admin role bindings",
			References: []string{
				"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
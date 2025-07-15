package nist

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type AccessControlRule struct{}

func NewAccessControlRule() *AccessControlRule {
	return &AccessControlRule{}
}

func (r *AccessControlRule) ID() string {
	return "NIST-4.6.1"
}

func (r *AccessControlRule) Title() string {
	return "Access control and RBAC"
}

func (r *AccessControlRule) Description() string {
	return "Service accounts should have minimal required permissions"
}

func (r *AccessControlRule) Standard() string {
	return "nist"
}

func (r *AccessControlRule) Section() string {
	return "4.6.1"
}

func (r *AccessControlRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *AccessControlRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
	k8sClient, ok := client.(*k8s.Client)
	if !ok {
		return nil, fmt.Errorf("expected k8s client")
	}

	var findings []types.Finding

	serviceAccounts, err := k8sClient.GetServiceAccounts(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get service accounts: %w", err)
	}

	for _, sa := range serviceAccounts.Items {
		if sa.Name == "default" {
			roleBindings, err := k8sClient.GetRoleBindings(ctx, sa.Namespace)
			if err != nil {
				continue
			}

			clusterRoleBindings, err := k8sClient.GetClusterRoleBindings(ctx)
			if err != nil {
				continue
			}

			hasBindings := false
			for _, rb := range roleBindings.Items {
				for _, subject := range rb.Subjects {
					if subject.Kind == "ServiceAccount" && subject.Name == sa.Name {
						hasBindings = true
						break
					}
				}
			}

			for _, crb := range clusterRoleBindings.Items {
				for _, subject := range crb.Subjects {
					if subject.Kind == "ServiceAccount" && subject.Name == sa.Name && subject.Namespace == sa.Namespace {
						hasBindings = true
						break
					}
				}
			}

			if hasBindings {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Default service account '%s' has explicit role bindings", sa.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "ServiceAccount",
						Name:      sa.Name,
						Namespace: sa.Namespace,
					},
					Remediation: "Use dedicated service accounts with minimal permissions instead of default",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
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
			Description: "Service accounts follow least privilege principle",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "ServiceAccount",
				Name: "all",
			},
			Remediation: "Continue using dedicated service accounts with minimal permissions",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
			},
		})
	}

	return findings, nil
}
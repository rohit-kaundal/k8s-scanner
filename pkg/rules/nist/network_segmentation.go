package nist

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type NetworkSegmentationRule struct{}

func NewNetworkSegmentationRule() *NetworkSegmentationRule {
	return &NetworkSegmentationRule{}
}

func (r *NetworkSegmentationRule) ID() string {
	return "NIST-4.3.1"
}

func (r *NetworkSegmentationRule) Title() string {
	return "Network segmentation and policies"
}

func (r *NetworkSegmentationRule) Description() string {
	return "Namespaces should have network policies to control traffic flow"
}

func (r *NetworkSegmentationRule) Standard() string {
	return "nist"
}

func (r *NetworkSegmentationRule) Section() string {
	return "4.3.1"
}

func (r *NetworkSegmentationRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *NetworkSegmentationRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
	k8sClient, ok := client.(*k8s.Client)
	if !ok {
		return nil, fmt.Errorf("expected k8s client")
	}

	var findings []types.Finding

	namespaces, err := k8sClient.GetNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespaces: %w", err)
	}

	for _, namespace := range namespaces.Items {
		if namespace.Name == "kube-system" || namespace.Name == "kube-public" || namespace.Name == "default" {
			continue
		}

		networkPolicies, err := k8sClient.GetNetworkPolicies(ctx, namespace.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get network policies for namespace %s: %w", namespace.Name, err)
		}

		if len(networkPolicies.Items) == 0 {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: fmt.Sprintf("Namespace '%s' has no network policies", namespace.Name),
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "Namespace",
					Name:      namespace.Name,
					Namespace: namespace.Name,
				},
				Remediation: "Implement network policies to control ingress and egress traffic",
				References: []string{
					"https://csrc.nist.gov/publications/detail/sp/800-190/final",
					"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
				},
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "All namespaces have network policies configured",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Namespace",
				Name: "all",
			},
			Remediation: "Continue implementing network policies for traffic control",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
			},
		})
	}

	return findings, nil
}
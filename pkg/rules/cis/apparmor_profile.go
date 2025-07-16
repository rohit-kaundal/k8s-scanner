package cis

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type AppArmorProfileRule struct{}

func NewAppArmorProfileRule() *AppArmorProfileRule {
	return &AppArmorProfileRule{}
}

func (r *AppArmorProfileRule) ID() string {
	return "CIS-5.1.9"
}

func (r *AppArmorProfileRule) Title() string {
	return "Minimize the admission of containers with AppArmor profile"
}

func (r *AppArmorProfileRule) Description() string {
	return "Containers should have AppArmor profiles applied for additional security"
}

func (r *AppArmorProfileRule) Standard() string {
	return "cis"
}

func (r *AppArmorProfileRule) Section() string {
	return "5.1.9"
}

func (r *AppArmorProfileRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *AppArmorProfileRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
			hasAppArmor := false
			
			if pod.Annotations != nil {
				for key := range pod.Annotations {
					if key == fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name) {
						hasAppArmor = true
						break
					}
				}
			}

			if !hasAppArmor {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' does not have an AppArmor profile", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Add AppArmor annotation: container.apparmor.security.beta.kubernetes.io/<container>: <profile>",
					References: []string{
						"https://kubernetes.io/docs/tutorials/security/apparmor/",
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
			Description: "All containers have AppArmor profiles configured",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue to use AppArmor profiles",
			References: []string{
				"https://kubernetes.io/docs/tutorials/security/apparmor/",
				"https://www.cisecurity.org/benchmark/kubernetes",
			},
		})
	}

	return findings, nil
}
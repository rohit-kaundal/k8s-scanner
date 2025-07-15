package nist

import (
	"context"
	"fmt"
	"strings"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type SecretManagementRule struct{}

func NewSecretManagementRule() *SecretManagementRule {
	return &SecretManagementRule{}
}

func (r *SecretManagementRule) ID() string {
	return "NIST-4.5.1"
}

func (r *SecretManagementRule) Title() string {
	return "Secret management and security"
}

func (r *SecretManagementRule) Description() string {
	return "Secrets should be properly managed and not exposed in environment variables"
}

func (r *SecretManagementRule) Standard() string {
	return "nist"
}

func (r *SecretManagementRule) Section() string {
	return "4.5.1"
}

func (r *SecretManagementRule) Severity() types.Severity {
	return types.SeverityHigh
}

func (r *SecretManagementRule) Check(ctx context.Context, client interface{}) ([]types.Finding, error) {
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
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					continue
				}
				
				if containsSecret(env.Name, env.Value) {
					finding := types.Finding{
						ID:          r.ID(),
						Title:       r.Title(),
						Description: fmt.Sprintf("Container '%s' may expose secrets in environment variables", container.Name),
						Standard:    r.Standard(),
						Section:     r.Section(),
						Severity:    r.Severity(),
						Status:      types.StatusWarning,
						Resource: types.Resource{
							Kind:      "Pod",
							Name:      pod.Name,
							Namespace: pod.Namespace,
						},
						Remediation: "Use Secret resources and valueFrom.secretKeyRef instead of plain text",
						References: []string{
							"https://csrc.nist.gov/publications/detail/sp/800-190/final",
							"https://kubernetes.io/docs/concepts/configuration/secret/",
						},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	secrets, err := k8sClient.GetSecrets(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	for _, secret := range secrets.Items {
		if secret.Type == "kubernetes.io/service-account-token" {
			continue
		}
		
		if len(secret.Data) == 0 {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: fmt.Sprintf("Secret '%s' has no data", secret.Name),
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "Secret",
					Name:      secret.Name,
					Namespace: secret.Namespace,
				},
				Remediation: "Remove unused secrets or populate with required data",
				References: []string{
					"https://csrc.nist.gov/publications/detail/sp/800-190/final",
					"https://kubernetes.io/docs/concepts/configuration/secret/",
				},
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "Secrets are properly managed",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Secret",
				Name: "all",
			},
			Remediation: "Continue using proper secret management",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/concepts/configuration/secret/",
			},
		})
	}

	return findings, nil
}

func containsSecret(name, value string) bool {
	secretPatterns := []string{
		"password", "passwd", "secret", "key", "token", "auth", "credential",
		"api_key", "apikey", "private_key", "access_key", "secret_key",
	}
	
	name = strings.ToLower(name)
	for _, pattern := range secretPatterns {
		if strings.Contains(name, pattern) && value != "" {
			return true
		}
	}
	return false
}
package nist

import (
	"context"
	"fmt"
	"strings"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type ImageSigningRule struct{}

func NewImageSigningRule() *ImageSigningRule {
	return &ImageSigningRule{}
}

func (r *ImageSigningRule) ID() string {
	return "NIST-4.8.1"
}

func (r *ImageSigningRule) Title() string {
	return "Image signing and verification"
}

func (r *ImageSigningRule) Description() string {
	return "Container images should be signed and verified for authenticity"
}

func (r *ImageSigningRule) Standard() string {
	return "nist"
}

func (r *ImageSigningRule) Section() string {
	return "4.8.1"
}

func (r *ImageSigningRule) Severity() types.Severity {
	return types.SeverityMedium
}

func (r *ImageSigningRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
			if !isTrustedRegistry(container.Image) {
				finding := types.Finding{
					ID:          r.ID(),
					Title:       r.Title(),
					Description: fmt.Sprintf("Container '%s' uses image from untrusted registry", container.Name),
					Standard:    r.Standard(),
					Section:     r.Section(),
					Severity:    r.Severity(),
					Status:      types.StatusWarning,
					Resource: types.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Remediation: "Use images from trusted registries and implement image signing verification",
					References: []string{
						"https://csrc.nist.gov/publications/detail/sp/800-190/final",
						"https://kubernetes.io/docs/concepts/containers/images/",
					},
				}
				findings = append(findings, finding)
			}
		}

		hasImagePolicy := false
		if pod.Annotations != nil {
			for key := range pod.Annotations {
				if strings.Contains(key, "image-policy") || strings.Contains(key, "cosign") {
					hasImagePolicy = true
					break
				}
			}
		}

		if !hasImagePolicy {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: fmt.Sprintf("Pod '%s' has no image verification policy", pod.Name),
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Implement image signing verification with tools like Cosign or Notary",
				References: []string{
					"https://csrc.nist.gov/publications/detail/sp/800-190/final",
					"https://kubernetes.io/docs/concepts/containers/images/",
				},
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "All images are from trusted sources with verification",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue using trusted registries and image verification",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/concepts/containers/images/",
			},
		})
	}

	return findings, nil
}

func isTrustedRegistry(image string) bool {
	trustedRegistries := []string{
		"gcr.io",
		"registry.k8s.io",
		"quay.io",
		"docker.io/library",
		"ghcr.io",
	}

	for _, registry := range trustedRegistries {
		if strings.HasPrefix(image, registry) {
			return true
		}
	}

	return false
}
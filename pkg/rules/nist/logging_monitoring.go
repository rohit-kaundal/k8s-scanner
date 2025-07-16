package nist

import (
	"context"
	"fmt"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/types"
)

type LoggingMonitoringRule struct{}

func NewLoggingMonitoringRule() *LoggingMonitoringRule {
	return &LoggingMonitoringRule{}
}

func (r *LoggingMonitoringRule) ID() string {
	return "NIST-4.7.1"
}

func (r *LoggingMonitoringRule) Title() string {
	return "Logging and monitoring"
}

func (r *LoggingMonitoringRule) Description() string {
	return "Pods should have proper logging configuration and monitoring setup"
}

func (r *LoggingMonitoringRule) Standard() string {
	return "nist"
}

func (r *LoggingMonitoringRule) Section() string {
	return "4.7.1"
}

func (r *LoggingMonitoringRule) Severity() types.Severity {
	return types.SeverityLow
}

func (r *LoggingMonitoringRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
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
		hasLogging := false
		hasMonitoring := false

		if pod.Annotations != nil {
			for key := range pod.Annotations {
				if key == "fluentd.io/enable" || key == "logging.coreos.com/enable" {
					hasLogging = true
				}
				if key == "prometheus.io/scrape" || key == "prometheus.io/port" {
					hasMonitoring = true
				}
			}
		}

		if !hasLogging {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: fmt.Sprintf("Pod '%s' has no logging configuration", pod.Name),
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Configure centralized logging with annotations or log collection agents",
				References: []string{
					"https://csrc.nist.gov/publications/detail/sp/800-190/final",
					"https://kubernetes.io/docs/concepts/cluster-administration/logging/",
				},
			}
			findings = append(findings, finding)
		}

		if !hasMonitoring {
			finding := types.Finding{
				ID:          r.ID(),
				Title:       r.Title(),
				Description: fmt.Sprintf("Pod '%s' has no monitoring configuration", pod.Name),
				Standard:    r.Standard(),
				Section:     r.Section(),
				Severity:    r.Severity(),
				Status:      types.StatusWarning,
				Resource: types.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Remediation: "Configure monitoring with prometheus annotations or monitoring agents",
				References: []string{
					"https://csrc.nist.gov/publications/detail/sp/800-190/final",
					"https://kubernetes.io/docs/concepts/cluster-administration/monitoring/",
				},
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: "All pods have proper logging and monitoring configuration",
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      types.StatusPassed,
			Resource: types.Resource{
				Kind: "Pod",
				Name: "all",
			},
			Remediation: "Continue maintaining logging and monitoring configurations",
			References: []string{
				"https://csrc.nist.gov/publications/detail/sp/800-190/final",
				"https://kubernetes.io/docs/concepts/cluster-administration/logging/",
			},
		})
	}

	return findings, nil
}
package cmd

import (
	"fmt"

	"k8s-scanner/pkg/scanner"
	"k8s-scanner/pkg/report"
	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
)

var (
	output     string
	outputFile string
	standards  []string
	namespace  string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scan on Kubernetes cluster",
	Long: `Scan the Kubernetes cluster for security misconfigurations according to
CIS Kubernetes Benchmark and NIST SP 800-190 standards.

Examples:
  k8s-scanner scan
  k8s-scanner scan --standards cis,nist
  k8s-scanner scan --output json
  k8s-scanner scan --namespace kube-system
  k8s-scanner scan --output json --file results.json
  k8s-scanner scan --output html --file report.html`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logrus.Info("Starting Kubernetes security scan")

		config := &scanner.Config{
			KubeConfig: kubeconfig,
			Standards:  standards,
			Namespace:  namespace,
		}

		s, err := scanner.New(config)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		results, err := s.Scan()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		reporter := report.NewReporter(output, outputFile)
		if err := reporter.Generate(results); err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}

		if outputFile != "" {
			logrus.WithFields(logrus.Fields{
				"findings": len(results.Findings),
				"file":     outputFile,
			}).Info("Scan completed and results saved to file")
		} else {
			logrus.WithField("findings", len(results.Findings)).Info("Scan completed")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	
	scanCmd.Flags().StringVarP(&output, "output", "o", "text", "Output format (text, json, yaml, html)")
	scanCmd.Flags().StringVarP(&outputFile, "file", "f", "", "Output file path (default: stdout)")
	scanCmd.Flags().StringSliceVarP(&standards, "standards", "s", []string{"cis", "nist"}, "Security standards to check (cis, nist)")
	scanCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Scan specific namespace (default: all namespaces)")
}
package cmd

import (
	"fmt"
	"time"

	"k8s-scanner/pkg/scanner"
	"k8s-scanner/pkg/report"
	"k8s-scanner/pkg/ui"
	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
)

var (
	output     string
	outputFile string
	standards  []string
	namespace  string
	quietMode  bool
	paginate   bool
	rulesDir   string
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
		// Create terminal UI
		terminalUI := ui.NewTerminalUI(quietMode)

		// Show banner only for text output
		if output == "text" && outputFile == "" {
			terminalUI.ShowBanner()
		}

		// Show scan start info
		if output == "text" && outputFile == "" {
			terminalUI.ShowScanStart(standards, namespace)
		}

		logrus.Info("Starting Kubernetes security scan")

		config := &scanner.Config{
			KubeConfig: kubeconfig,
			Standards:  standards,
			Namespace:  namespace,
			RulesDir:   rulesDir,
		}

		s, err := scanner.New(config)
		if err != nil {
			if output == "text" && outputFile == "" {
				terminalUI.ShowError(fmt.Sprintf("failed to create scanner: %v", err))
			}
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// Set quiet mode for scanner  
		s.SetQuietMode(quietMode || output != "text" || outputFile != "")

		// Record start time for duration calculation
		startTime := time.Now()

		// Show scanning step
		if output == "text" && outputFile == "" {
			terminalUI.ShowStep("Analyzing cluster resources...")
		}

		results, err := s.Scan()
		if err != nil {
			if output == "text" && outputFile == "" {
				terminalUI.ShowError(fmt.Sprintf("scan failed: %v", err))
			}
			return fmt.Errorf("scan failed: %w", err)
		}

		// Show scan completion
		if output == "text" && outputFile == "" {
			duration := time.Since(startTime)
			terminalUI.ShowScanComplete(len(results.Findings), duration)
		}

		reporter := report.NewReporter(output, outputFile)
		if err := reporter.Generate(results); err != nil {
			if output == "text" && outputFile == "" {
				terminalUI.ShowError(fmt.Sprintf("failed to generate report: %v", err))
			}
			return fmt.Errorf("failed to generate report: %w", err)
		}

		if outputFile != "" {
			logrus.WithFields(logrus.Fields{
				"findings": len(results.Findings),
				"file":     outputFile,
			}).Info("Scan completed and results saved to file")
			if output == "text" {
				terminalUI.ShowInfo(fmt.Sprintf("Results saved to: %s", outputFile))
			}
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
	scanCmd.Flags().BoolVarP(&quietMode, "quiet", "q", false, "Quiet mode: disable typing effects and progress bars")
	scanCmd.Flags().StringVarP(&rulesDir, "rules-dir", "r", "", "Directory containing rule JSON files (default: config/rules)")
}
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
)

var (
	kubeconfig string
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "k8s-scanner",
	Short: "Kubernetes security scanner for CIS and NIST compliance",
	Long: `A comprehensive Kubernetes security scanner that checks for misconfigurations
against CIS Kubernetes Benchmark and NIST SP 800-190 standards.

The scanner connects to your Kubernetes cluster and evaluates resources
for security compliance, providing detailed reports with remediation guidance.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: ~/.kube/config)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
}
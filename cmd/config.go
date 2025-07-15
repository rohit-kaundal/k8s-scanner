package cmd

import (
	"fmt"
	"os"

	"k8s-scanner/pkg/scanner"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show configuration",
	Long:  `Display the current configuration including all rules and settings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := scanner.LoadConfig("")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		
		return encoder.Encode(config)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
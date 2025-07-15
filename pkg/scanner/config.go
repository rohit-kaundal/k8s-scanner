package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ConfigFile struct {
	Scanner ScannerConfig `yaml:"scanner"`
}

type ScannerConfig struct {
	KubeConfig         string         `yaml:"kubeconfig"`
	Standards          []string       `yaml:"standards"`
	Namespace          string         `yaml:"namespace"`
	ExcludeNamespaces  []string       `yaml:"exclude_namespaces"`
	Output             OutputConfig   `yaml:"output"`
	Rules              RulesConfig    `yaml:"rules"`
}

type OutputConfig struct {
	Format  string `yaml:"format"`
	Verbose bool   `yaml:"verbose"`
}

type RulesConfig struct {
	CIS  StandardConfig `yaml:"cis"`
	NIST StandardConfig `yaml:"nist"`
}

type StandardConfig struct {
	Enabled bool                   `yaml:"enabled"`
	Rules   map[string]RuleConfig  `yaml:"rules"`
}

type RuleConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Severity string `yaml:"severity"`
}

func LoadConfig(configPath string) (*ConfigFile, error) {
	if configPath == "" {
		configPath = findDefaultConfig()
	}

	if configPath == "" {
		return getDefaultConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ConfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func findDefaultConfig() string {
	locations := []string{
		"config/config.yaml",
		"./config.yaml",
		"~/.k8s-scanner/config.yaml",
		"/etc/k8s-scanner/config.yaml",
	}

	for _, location := range locations {
		if location[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			location = filepath.Join(home, location[2:])
		}

		if _, err := os.Stat(location); err == nil {
			return location
		}
	}

	return ""
}

func getDefaultConfig() *ConfigFile {
	return &ConfigFile{
		Scanner: ScannerConfig{
			KubeConfig: "",
			Standards:  []string{"cis", "nist"},
			Namespace:  "",
			ExcludeNamespaces: []string{
				"kube-system",
				"kube-public",
				"kube-node-lease",
			},
			Output: OutputConfig{
				Format:  "text",
				Verbose: false,
			},
			Rules: RulesConfig{
				CIS: StandardConfig{
					Enabled: true,
					Rules: map[string]RuleConfig{
						"CIS-5.1.1":  {Enabled: true, Severity: "high"},
						"CIS-5.1.2":  {Enabled: true, Severity: "high"},
						"CIS-5.1.3":  {Enabled: true, Severity: "high"},
						"CIS-5.1.4":  {Enabled: true, Severity: "medium"},
						"CIS-5.1.5":  {Enabled: true, Severity: "high"},
						"CIS-5.1.6":  {Enabled: true, Severity: "high"},
						"CIS-5.1.7":  {Enabled: true, Severity: "high"},
						"CIS-5.1.8":  {Enabled: true, Severity: "medium"},
						"CIS-5.1.9":  {Enabled: true, Severity: "medium"},
						"CIS-5.1.10": {Enabled: true, Severity: "medium"},
					},
				},
				NIST: StandardConfig{
					Enabled: true,
					Rules: map[string]RuleConfig{
						"NIST-4.1.1": {Enabled: true, Severity: "high"},
						"NIST-4.2.1": {Enabled: true, Severity: "high"},
						"NIST-4.3.1": {Enabled: true, Severity: "medium"},
						"NIST-4.4.1": {Enabled: true, Severity: "medium"},
						"NIST-4.5.1": {Enabled: true, Severity: "high"},
						"NIST-4.6.1": {Enabled: true, Severity: "medium"},
						"NIST-4.7.1": {Enabled: true, Severity: "low"},
						"NIST-4.8.1": {Enabled: true, Severity: "medium"},
					},
				},
			},
		},
	}
}

func (c *ConfigFile) IsRuleEnabled(ruleID string) bool {
	if c.Scanner.Rules.CIS.Enabled {
		if ruleConfig, exists := c.Scanner.Rules.CIS.Rules[ruleID]; exists {
			return ruleConfig.Enabled
		}
	}

	if c.Scanner.Rules.NIST.Enabled {
		if ruleConfig, exists := c.Scanner.Rules.NIST.Rules[ruleID]; exists {
			return ruleConfig.Enabled
		}
	}

	return true
}

func (c *ConfigFile) GetRuleSeverity(ruleID string) string {
	if c.Scanner.Rules.CIS.Enabled {
		if ruleConfig, exists := c.Scanner.Rules.CIS.Rules[ruleID]; exists {
			return ruleConfig.Severity
		}
	}

	if c.Scanner.Rules.NIST.Enabled {
		if ruleConfig, exists := c.Scanner.Rules.NIST.Rules[ruleID]; exists {
			return ruleConfig.Severity
		}
	}

	return "medium"
}
package rules

import (
	"fmt"
	"path/filepath"

	"k8s-scanner/pkg/types"
	"k8s-scanner/pkg/rules/json"
)

// RegisterJSONRules loads and registers rules from JSON files
func RegisterJSONRules(registry *types.RuleRegistry, rulesDir string) error {
	rules, err := json.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to load JSON rules: %v", err)
	}

	for _, rule := range rules {
		registry.Register(rule)
	}

	return nil
}

// RegisterCISRules loads CIS rules from JSON file
func RegisterCISRules(registry *types.RuleRegistry, rulesDir string) error {
	cisFile := filepath.Join(rulesDir, "cis.json")
	rules, err := json.LoadRulesFromFile(cisFile)
	if err != nil {
		return fmt.Errorf("failed to load CIS rules: %v", err)
	}

	for _, rule := range rules {
		registry.Register(rule)
	}

	return nil
}

// RegisterNISTRules loads NIST rules from JSON file
func RegisterNISTRules(registry *types.RuleRegistry, rulesDir string) error {
	nistFile := filepath.Join(rulesDir, "nist.json")
	rules, err := json.LoadRulesFromFile(nistFile)
	if err != nil {
		return fmt.Errorf("failed to load NIST rules: %v", err)
	}

	for _, rule := range rules {
		registry.Register(rule)
	}

	return nil
}

// Legacy support - keeping for backward compatibility
// TODO: Remove once migration is complete
func RegisterCISRulesLegacy(registry *types.RuleRegistry) {
	// Legacy hardcoded rules - deprecated
	// These will be removed in favor of JSON-based rules
}

func RegisterNISTRulesLegacy(registry *types.RuleRegistry) {
	// Legacy hardcoded rules - deprecated
	// These will be removed in favor of JSON-based rules
}
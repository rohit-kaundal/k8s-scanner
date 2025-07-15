package scanner

import (
	"k8s-scanner/pkg/types"
)

// Re-export types for backward compatibility
type Config = types.Config
type Scanner = types.Scanner
type ScanResults = types.ScanResults
type Summary = types.Summary
type Finding = types.Finding
type Severity = types.Severity
type Status = types.Status
type Resource = types.Resource
type Rule = types.Rule
type RuleRegistry = types.RuleRegistry

const (
	SeverityLow      = types.SeverityLow
	SeverityMedium   = types.SeverityMedium
	SeverityHigh     = types.SeverityHigh
	SeverityCritical = types.SeverityCritical
)

const (
	StatusPassed  = types.StatusPassed
	StatusFailed  = types.StatusFailed
	StatusWarning = types.StatusWarning
)

func NewRuleRegistry() *RuleRegistry {
	return types.NewRuleRegistry()
}
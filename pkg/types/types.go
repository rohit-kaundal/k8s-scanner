package types

import (
	"context"
	"time"
)

type Config struct {
	KubeConfig string
	Standards  []string
	Namespace  string
}

type Scanner interface {
	Scan() (*ScanResults, error)
	SetQuietMode(quiet bool)
}

type ScanResults struct {
	Timestamp time.Time  `json:"timestamp"`
	Summary   Summary    `json:"summary"`
	Findings  []Finding  `json:"findings"`
}

type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
}

type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Standard    string    `json:"standard"`
	Section     string    `json:"section"`
	Severity    Severity  `json:"severity"`
	Status      Status    `json:"status"`
	Resource    Resource  `json:"resource"`
	Remediation string    `json:"remediation"`
	References  []string  `json:"references"`
}

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Status string

const (
	StatusPassed  Status = "passed"
	StatusFailed  Status = "failed"
	StatusWarning Status = "warning"
)

type Resource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type Rule interface {
	ID() string
	Title() string
	Description() string
	Standard() string
	Section() string
	Severity() Severity
	Check(ctx context.Context, client interface{}, config *Config) ([]Finding, error)
}

type RuleRegistry struct {
	rules []Rule
}

func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		rules: make([]Rule, 0),
	}
}

func (r *RuleRegistry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

func (r *RuleRegistry) GetRules() []Rule {
	return r.rules
}

func (r *RuleRegistry) GetRulesByStandard(standard string) []Rule {
	var filtered []Rule
	for _, rule := range r.rules {
		if rule.Standard() == standard {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}
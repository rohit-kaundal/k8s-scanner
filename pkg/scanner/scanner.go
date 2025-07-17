package scanner

import (
	"context"
	"fmt"
	"time"

	"k8s-scanner/pkg/k8s"
	"k8s-scanner/pkg/rules"
	"k8s-scanner/pkg/ui"
	"github.com/sirupsen/logrus"
)

type scanner struct {
	client     *k8s.Client
	registry   *RuleRegistry
	config     *Config
	terminalUI *ui.TerminalUI
}

func New(config *Config) (Scanner, error) {
	client, err := k8s.NewClient(config.KubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	registry := NewRuleRegistry()
	
	// Set default rules directory if not specified
	rulesDir := config.RulesDir
	if rulesDir == "" {
		rulesDir = "config/rules"
	}
	
	for _, standard := range config.Standards {
		switch standard {
		case "cis":
			err := rules.RegisterCISRules(registry, rulesDir)
			if err != nil {
				logrus.WithError(err).WithField("standard", standard).Error("Failed to register CIS rules")
			}
		case "nist":
			err := rules.RegisterNISTRules(registry, rulesDir)
			if err != nil {
				logrus.WithError(err).WithField("standard", standard).Error("Failed to register NIST rules")
			}
		default:
			logrus.WithField("standard", standard).Warn("Unknown standard, skipping")
		}
	}

	return &scanner{
		client:     client,
		registry:   registry,
		config:     config,
		terminalUI: ui.NewTerminalUI(false), // Default to non-quiet mode
	}, nil
}

// SetQuietMode sets the quiet mode for the scanner's terminal UI
func (s *scanner) SetQuietMode(quiet bool) {
	s.terminalUI = ui.NewTerminalUI(quiet)
}

func (s *scanner) Scan() (*ScanResults, error) {
	ctx := context.Background()
	
	logrus.Info("Starting security scan")
	start := time.Now()

	var allFindings []Finding
	var rulesToRun []Rule

	if len(s.config.Standards) == 0 {
		rulesToRun = s.registry.GetRules()
	} else {
		for _, standard := range s.config.Standards {
			rulesToRun = append(rulesToRun, s.registry.GetRulesByStandard(standard)...)
		}
	}

	// Create progress bar for rule execution
	progressBar := s.terminalUI.CreateProgressBar(len(rulesToRun), "Executing security rules")

	for _, rule := range rulesToRun {
		logrus.WithFields(logrus.Fields{
			"rule_id":   rule.ID(),
			"standard":  rule.Standard(),
			"severity":  rule.Severity(),
		}).Debug("Running rule")

		findings, err := rule.Check(ctx, s.client, s.config)
		if err != nil {
			logrus.WithError(err).WithField("rule_id", rule.ID()).Error("Rule check failed")
			progressBar.Add(1)
			continue
		}

		allFindings = append(allFindings, findings...)
		progressBar.Add(1)
	}

	summary := s.calculateSummary(allFindings)
	
	results := &ScanResults{
		Timestamp: start,
		Summary:   summary,
		Findings:  allFindings,
	}

	duration := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"duration": duration,
		"findings": len(allFindings),
		"passed":   summary.Passed,
		"failed":   summary.Failed,
		"warnings": summary.Warnings,
	}).Info("Scan completed")

	return results, nil
}

func (s *scanner) calculateSummary(findings []Finding) Summary {
	summary := Summary{
		Total: len(findings),
	}

	for _, finding := range findings {
		switch finding.Status {
		case StatusPassed:
			summary.Passed++
		case StatusFailed:
			summary.Failed++
		case StatusWarning:
			summary.Warnings++
		}
	}

	return summary
}
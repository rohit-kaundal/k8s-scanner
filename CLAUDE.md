# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based Kubernetes security scanner that checks for misconfigurations against CIS Kubernetes Benchmark and NIST SP 800-190 standards. The scanner connects to Kubernetes clusters and evaluates resources for security compliance.

## Commands

### Development Commands
- `go run main.go` - Run the scanner
- `go build -o k8s-scanner` - Build the binary
- `go test ./...` - Run all tests
- `go mod tidy` - Clean up dependencies

### Scanner Commands
- `./k8s-scanner scan` - Run security scan on current cluster
- `./k8s-scanner scan --kubeconfig ~/.kube/config` - Scan with specific kubeconfig
- `./k8s-scanner scan --output json` - Output results in JSON format
- `./k8s-scanner scan --output json --file results.json` - Save results to file
- `./k8s-scanner scan --output html --file report.html` - Generate HTML report
- `./k8s-scanner scan --standards cis,nist` - Run specific standards
- `./k8s-scanner scan --rules-dir /path/to/rules` - Use custom rules directory

## Architecture

### Core Components
- **main.go**: CLI entry point using cobra framework
- **pkg/scanner/**: Core scanning engine that orchestrates security checks
- **pkg/rules/**: Rule implementations for CIS and NIST standards
- **pkg/k8s/**: Kubernetes client wrapper using client-go
- **pkg/report/**: Output formatting and reporting system
- **cmd/**: CLI command implementations
- **config/**: Default rule configurations and customization

### Key Packages
- Uses `k8s.io/client-go` for Kubernetes API interaction
- Uses `github.com/spf13/cobra` for CLI framework
- Uses `github.com/sirupsen/logrus` for structured logging
- Uses `gopkg.in/yaml.v3` for configuration parsing

### Security Standards
- **CIS Kubernetes Benchmark**: Control plane, node security, policies, logging
- **NIST SP 800-190**: Image security, registry security, runtime security, host security

### Rule System
Rules are implemented as pluggable components that can be:
- Enabled/disabled via configuration
- Customized with severity levels
- Extended with custom implementations
- Defined externally using JSON files for easy maintenance

#### JSON-Based Rules
Rules are now defined in external JSON files located in `config/rules/`:
- `config/rules/cis.json` - CIS Kubernetes Benchmark rules
- `config/rules/nist.json` - NIST SP 800-190 rules
- `config/rules/schema.json` - JSON schema for rule validation

#### Rule Structure
Each rule is defined with the following structure:
```json
{
  "id": "CIS-5.1.2",
  "title": "Rule title",
  "description": "Rule description",
  "standard": "cis",
  "section": "5.1.2",
  "severity": "high",
  "enabled": true,
  "check": {
    "type": "pod",
    "conditions": [
      {
        "field": "spec.containers[*].securityContext.privileged",
        "operator": "equals",
        "value": true,
        "expected_result": "fail"
      }
    ]
  },
  "remediation": "How to fix this issue",
  "references": ["https://example.com/docs"]
}
```

#### Field Path Evaluation
The rule engine supports complex field path evaluation:
- Nested field access: `spec.containers[*].securityContext.privileged`
- Array element access: `spec.containers[*].env[*].value`
- Metadata access: `metadata.labels['app.kubernetes.io/name']`

#### Supported Operators
- `equals` / `not_equals` - Exact value matching
- `exists` / `not_exists` - Field presence checking
- `contains` / `not_contains` - Substring matching
- `matches` / `not_matches` - Regular expression matching
- `greater_than` / `less_than` - Numeric comparisons

### Authentication
The scanner supports multiple authentication methods:
- Default kubeconfig (~/.kube/config)
- Service account tokens (for in-cluster deployment)
- Custom kubeconfig files
- Environment variables for cloud providers

## Development Guidelines

### Adding New Rules

#### Method 1: JSON-Based Rules (Recommended)
1. Create or edit JSON files in `config/rules/` directory
2. Define rules following the JSON schema structure
3. Test rules using `--rules-dir` flag
4. No code changes required

#### Method 2: Go-Based Rules (Advanced)
1. Create rule struct implementing the Rule interface in pkg/rules/
2. Add rule to appropriate standard (CIS or NIST)
3. Include test cases with mock Kubernetes resources
4. Update configuration files to include the new rule

#### Rule Testing
- Use `--rules-dir` flag to test custom rules
- Validate JSON structure against schema
- Test against sample Kubernetes resources

### Testing
- Use table-driven tests for rule validation
- Mock Kubernetes client interactions
- Test both positive and negative scenarios
- Include integration tests with real cluster resources

### Error Handling
- Use structured logging with logrus
- Provide actionable error messages
- Include remediation guidance in findings
- Handle network timeouts and API errors gracefully
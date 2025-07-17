# K8s Security Scanner

A comprehensive Kubernetes security scanner that checks for misconfigurations against CIS Kubernetes Benchmark and NIST SP 800-190 standards.

## Features

- **CIS Kubernetes Benchmark**: Implements security controls from the Center for Internet Security
- **NIST SP 800-190**: Follows NIST Application Container Security Guide
- **JSON-Based Rules**: External rule definitions for easy customization and maintenance
- **Multiple Output Formats**: Text, JSON, YAML, and HTML reporting
- **File Output**: Save scan results to files for later analysis or CI/CD integration
- **Configurable Rules**: Enable/disable specific rules and customize severity levels
- **Namespace Filtering**: Scan specific namespaces or exclude system namespaces
- **Extensible Architecture**: Easy to add new rules and standards without code changes

## Installation

### From Source

```bash
git clone https://github.com/rohit-kaundal/k8s-scanner.git
cd k8s-scanner
go build -o k8s-scanner
```

### Using Go Install

```bash
go install github.com/rohit-kaundal/k8s-scanner@latest
```

## Quick Start

1. **Basic scan with default settings:**
   ```bash
   ./k8s-scanner scan
   ```

2. **Scan with JSON output:**
   ```bash
   ./k8s-scanner scan --output json
   ```

3. **Save results to file:**
   ```bash
   ./k8s-scanner scan --output json --file results.json
   ```

4. **Generate HTML report:**
   ```bash
   ./k8s-scanner scan --output html --file security-report.html
   ```

5. **Scan specific namespace:**
   ```bash
   ./k8s-scanner scan --namespace production
   ```

6. **Scan with specific standards:**
   ```bash
   ./k8s-scanner scan --standards cis,nist
   ```

7. **Use custom rules directory:**
   ```bash
   ./k8s-scanner scan --rules-dir /path/to/custom/rules
   ```


## Usage

### Command Line Options

```bash
k8s-scanner scan [flags]

Flags:
  -f, --file string            Output file path (default: stdout)
  -h, --help                   help for scan
      --kubeconfig string      Path to kubeconfig file (default: ~/.kube/config)
  -n, --namespace string       Scan specific namespace (default: all namespaces)
  -o, --output string          Output format (text, json, yaml, html) (default "text")
  -r, --rules-dir string       Directory containing rule JSON files (default: config/rules)
  -s, --standards strings      Security standards to check (cis, nist) (default [cis,nist])
  -v, --verbose                Enable verbose logging
```

### HTML Reports

The scanner can generate comprehensive HTML reports that are perfect for sharing with teams and stakeholders:

```bash
# Generate interactive HTML report
./k8s-scanner scan --output html --file security-report.html
```

The HTML report includes:
- **Executive Summary**: Overview of security posture with key metrics
- **Interactive Filtering**: Filter findings by status, severity, or standard
- **Detailed Findings**: Each finding includes description, remediation steps, and references
- **Professional Styling**: Clean, modern design suitable for presentations
- **Responsive Design**: Works on desktop and mobile devices
- **Standards Grouping**: Organized by CIS and NIST standards for easy navigation

### File Output

The scanner supports saving results to files for later analysis or integration with other tools:

```bash
# Save JSON results to file
./k8s-scanner scan --output json --file scan-results.json

# Save YAML results to file
./k8s-scanner scan --output yaml --file scan-results.yaml

# Save text report to file
./k8s-scanner scan --output text --file scan-report.txt

# Generate comprehensive HTML report
./k8s-scanner scan --output html --file security-report.html

# Combine with other options
./k8s-scanner scan --namespace production --standards cis --output json --file production-cis-scan.json
```

### JSON-Based Rules

The scanner uses external JSON files to define security rules, making it easy to customize and maintain without code changes.

#### Rule Structure

Rules are defined in JSON format with the following structure:

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "id": "CIS-5.1.2",
      "title": "Minimize the admission of privileged containers",
      "description": "Do not generally permit containers to be run with the securityContext.privileged flag set to true.",
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
      "remediation": "Create a PSP as described in the CIS documentation, ensuring that the .spec.privileged field is omitted or set to false.",
      "references": [
        "https://kubernetes.io/docs/concepts/policy/pod-security-policy/"
      ]
    }
  ]
}
```

#### Rule Directories

By default, rules are loaded from the `config/rules/` directory:
- `config/rules/cis.json` - CIS Kubernetes Benchmark rules
- `config/rules/nist.json` - NIST SP 800-190 rules
- `config/rules/schema.json` - JSON schema for rule validation

#### Custom Rule Directories

You can specify a custom rules directory:

```bash
./k8s-scanner scan --rules-dir /path/to/custom/rules
```

#### Supported Field Operators

The rule engine supports various operators for field evaluation:

- `equals` / `not_equals` - Exact value matching
- `exists` / `not_exists` - Field presence checking
- `contains` / `not_contains` - Substring matching
- `matches` / `not_matches` - Regular expression matching
- `greater_than` / `less_than` - Numeric comparisons

#### Array Field Access

Use `[*]` notation to access array elements:

```json
{
  "field": "spec.containers[*].securityContext.privileged",
  "operator": "equals",
  "value": true,
  "expected_result": "fail"
}
```

#### Adding Custom Rules

1. Create a new JSON file in your rules directory
2. Define rules following the JSON schema
3. Run the scanner with your custom rules directory

### Configuration File

Create a `config/config.yaml` file to customize scanner behavior:

```yaml
scanner:
  kubeconfig: ""
  standards:
    - cis
    - nist
  namespace: ""
  exclude_namespaces:
    - kube-system
    - kube-public
  output:
    format: text
    verbose: false
  rules:
    cis:
      enabled: true
      rules:
        CIS-5.1.1:
          enabled: true
          severity: high
    nist:
      enabled: true
      rules:
        NIST-4.1.1:
          enabled: true
          severity: high
```

## Security Standards

### CIS Kubernetes Benchmark

The scanner implements key CIS Kubernetes Benchmark controls:

- **CIS-5.1.1**: Cluster-admin role usage
- **CIS-5.1.2**: Privileged container admission
- **CIS-5.1.3**: Privilege escalation prevention
- **CIS-5.1.4**: Capabilities management
- **CIS-5.1.5**: Host network restrictions
- **CIS-5.1.6**: Host PID restrictions
- **CIS-5.1.7**: Host IPC restrictions
- **CIS-5.1.8**: Seccomp profile requirements
- **CIS-5.1.9**: AppArmor profile requirements
- **CIS-5.1.10**: Service account token management

### NIST SP 800-190

The scanner implements NIST Application Container Security Guide controls:

- **NIST-4.1.1**: Image vulnerability management
- **NIST-4.2.1**: Container runtime security
- **NIST-4.3.1**: Network segmentation
- **NIST-4.4.1**: Resource limits and quotas
- **NIST-4.5.1**: Secret management
- **NIST-4.6.1**: Access control and RBAC
- **NIST-4.7.1**: Logging and monitoring
- **NIST-4.8.1**: Image signing and verification

## Example Output

### Text Format

```
✅ Scan completed successfully!
📊 Total findings: 42
⏱️  Duration: 5.2s

🔐 KUBERNETES SECURITY SCAN REPORT
════════════════════════════════════════════════════════════════════════════════

📅 SCAN METADATA
────────────────────────────────────────
Scan Time: 2024-01-15T10:30:00Z

📋 SCAN SUMMARY
────────────────────────────────────────
Total Checks: 42
✅ Passed: 12 (28.6%)
❌ Failed: 8 (19.0%)
⚠️  Warnings: 22 (52.4%)

⚠️  Some warnings found. Consider reviewing them.

🔍 VULNERABILITY ANALYSIS SUMMARY
════════════════════════════════════════════════════════════════════════════════

📊 OVERALL STATISTICS
──────────────────────────────────────────────────
Total Security Checks: 42
✅ Passed: 12
❌ Failed: 8
⚠️  Warnings: 22
Pass Rate: 28.6%

🎯 SEVERITY DISTRIBUTION
──────────────────────────────────────────────────
🟠 HIGH: 12 (40.0%)
  [████████████░░░░░░░░░░░░░░░░░░]
🟡 MEDIUM: 15 (50.0%)
  [███████████████░░░░░░░░░░░░░░░]
🔵 LOW: 3 (10.0%)
  [███░░░░░░░░░░░░░░░░░░░░░░░░░░░]

📋 STANDARD DISTRIBUTION
──────────────────────────────────────────────────
📖 CIS: 18 (60.0%)
  [██████████████████░░░░░░░]
📖 NIST: 12 (40.0%)
  [████████████░░░░░░░░░░░░░]

🔥 TOP VULNERABILITIES
──────────────────────────────────────────────────
1. Minimize the admission of containers with allowPrivilegeEscalation
   Standard: CIS | Severity: 🟠 HIGH | Count: 6
   Affected: Pod/production/web-app-7c88d7ccdc-z6qfx, Pod/production/api-server-dcd676b9b-djcms, Pod/staging/worker-f5c9f976c-pct89... and 3 more
   Container allows privilege escalation

2. Image signing and verification
   Standard: NIST | Severity: 🟡 MEDIUM | Count: 5
   Affected: Pod/production/web-app-7c88d7ccdc-z6qfx, Pod/production/api-server-dcd676b9b-djcms, Pod/staging/worker-f5c9f976c-pct89... and 2 more
   Container uses image from untrusted registry

3. Secret management and security
   Standard: NIST | Severity: 🟠 HIGH | Count: 4
   Affected: Pod/production/web-app-7c88d7ccdc-z6qfx, Pod/production/api-server-dcd676b9b-djcms
   Container may expose secrets in environment variables

4. Minimize the admission of containers with capabilities
   Standard: CIS | Severity: 🟠 HIGH | Count: 4
   Affected: Pod/production/web-app-7c88d7ccdc-z6qfx, Pod/production/api-server-dcd676b9b-djcms, Pod/staging/worker-f5c9f976c-pct89... and 1 more
   Container has excessive capabilities

5. Container runtime security
   Standard: NIST | Severity: 🟡 MEDIUM | Count: 3
   Affected: Pod/production/web-app-7c88d7ccdc-z6qfx, Pod/production/api-server-dcd676b9b-djcms, Pod/staging/worker-f5c9f976c-pct89
   Container has no security context


⚠️  CRITICAL RESOURCES
──────────────────────────────────────────────────
1. Pod/production/web-app-7c88d7ccdc-z6qfx
   Total Issues: 8
   Severity Breakdown: HIGH: 4 | MEDIUM: 3 | LOW: 1
   Top Issues: Minimize the admission of containers with allowPrivilegeEscalation, Minimize the admission of containers with capabilities... and 6 more

2. Pod/production/api-server-dcd676b9b-djcms
   Total Issues: 7
   Severity Breakdown: HIGH: 3 | MEDIUM: 3 | LOW: 1
   Top Issues: Minimize the admission of containers with allowPrivilegeEscalation, Secret management and security... and 5 more

3. Pod/staging/worker-f5c9f976c-pct89
   Total Issues: 6
   Severity Breakdown: HIGH: 2 | MEDIUM: 3 | LOW: 1
   Top Issues: Minimize the admission of containers with allowPrivilegeEscalation, Image signing and verification... and 4 more

4. Pod/staging/database-b6684f856-h6wjh
   Total Issues: 5
   Severity Breakdown: HIGH: 1 | MEDIUM: 3 | LOW: 1
   Top Issues: Container runtime security, Logging and monitoring... and 3 more

5. Pod/development/test-app-85bb59d798-456vt
   Total Issues: 4
   Severity Breakdown: MEDIUM: 3 | LOW: 1
   Top Issues: Image signing and verification, Network segmentation... and 2 more
```

### JSON Format

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "summary": {
    "total": 15,
    "passed": 8,
    "failed": 5,
    "warnings": 2
  },
  "findings": [
    {
      "id": "CIS-5.1.2",
      "title": "Minimize the admission of privileged containers",
      "description": "Container 'nginx' is running in privileged mode",
      "standard": "cis",
      "section": "5.1.2",
      "severity": "high",
      "status": "failed",
      "resource": {
        "kind": "Pod",
        "name": "nginx-pod",
        "namespace": "default"
      },
      "remediation": "Remove privileged: true from container security context",
      "references": [
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
      ]
    }
  ]
}
```

## Authentication

The scanner supports multiple authentication methods:

1. **Default kubeconfig**: `~/.kube/config`
2. **Custom kubeconfig**: `--kubeconfig /path/to/config`
3. **In-cluster**: Automatic when running inside Kubernetes
4. **Environment variables**: Cloud provider specific

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for new rules
5. Submit a pull request

### Adding New Rules

There are two ways to add new rules:

#### Method 1: JSON-Based Rules (Recommended)

1. Create a new JSON file in your rules directory or edit existing ones
2. Define rules following the JSON schema structure
3. Test your rules using the `--rules-dir` flag
4. No code changes required!

Example:
```json
{
  "version": "1.0.0",
  "rules": [
    {
      "id": "CUSTOM-1.0.1",
      "title": "Custom security rule",
      "description": "Check for custom security configuration",
      "standard": "custom",
      "section": "1.0.1",
      "severity": "medium",
      "enabled": true,
      "check": {
        "type": "pod",
        "conditions": [
          {
            "field": "metadata.labels['security.custom/enabled']",
            "operator": "equals",
            "value": "true",
            "expected_result": "pass"
          }
        ]
      },
      "remediation": "Add the security.custom/enabled=true label to your pods",
      "references": ["https://example.com/custom-security-docs"]
    }
  ]
}
```

#### Method 2: Go-Based Rules (Advanced)

1. Create a new rule file in `pkg/rules/cis/` or `pkg/rules/nist/`
2. Implement the `Rule` interface
3. Register the rule in `pkg/rules/rules.go`
4. Add rule configuration to `config/config.yaml`
5. Add tests for the rule

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)

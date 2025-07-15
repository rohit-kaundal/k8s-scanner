# K8s Security Scanner

A comprehensive Kubernetes security scanner that checks for misconfigurations against CIS Kubernetes Benchmark and NIST SP 800-190 standards.

## Features

- **CIS Kubernetes Benchmark**: Implements security controls from the Center for Internet Security
- **NIST SP 800-190**: Follows NIST Application Container Security Guide
- **Multiple Output Formats**: Text, JSON, YAML, and HTML reporting
- **File Output**: Save scan results to files for later analysis or CI/CD integration
- **Configurable Rules**: Enable/disable specific rules and customize severity levels
- **Namespace Filtering**: Scan specific namespaces or exclude system namespaces
- **Extensible Architecture**: Easy to add new rules and standards

## Installation

### From Source

```bash
git clone https://github.com/your-org/k8s-scanner.git
cd k8s-scanner
go build -o k8s-scanner
```

### Using Go Install

```bash
go install github.com/your-org/k8s-scanner@latest
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
Kubernetes Security Scan Report
===============================

Scan Time: 2024-01-15T10:30:00Z
Total Findings: 15
Passed: 8
Failed: 5
Warnings: 2

CIS Standard
------------
ID           Title                                    Severity  Status   Resource
CIS-5.1.2    Minimize privileged containers          high      failed   Pod/nginx-pod
CIS-5.1.3    Minimize privilege escalation           high      failed   Pod/app-pod

Failed Checks
=============

[CIS-5.1.2] Minimize the admission of privileged containers
Standard: CIS (Section 5.1.2)
Severity: high
Status: failed
Resource: Pod/nginx-pod in namespace default
Description: Container 'nginx' is running in privileged mode
Remediation: Remove privileged: true from container security context
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
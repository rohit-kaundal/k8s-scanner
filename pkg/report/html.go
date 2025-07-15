package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"k8s-scanner/pkg/scanner"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Security Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .summary-card.total .number { color: #667eea; }
        .summary-card.passed .number { color: #4CAF50; }
        .summary-card.failed .number { color: #f44336; }
        .summary-card.warnings .number { color: #ff9800; }
        
        .standards-section {
            margin-bottom: 30px;
        }
        
        .standard-header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .standard-header h2 {
            color: #333;
            font-size: 1.8em;
            margin-bottom: 10px;
        }
        
        .standard-header p {
            color: #666;
            font-size: 1.1em;
        }
        
        .findings-grid {
            display: grid;
            gap: 20px;
        }
        
        .finding-card {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .finding-card:hover {
            transform: translateY(-2px);
        }
        
        .finding-header {
            padding: 20px;
            border-left: 4px solid #ddd;
        }
        
        .finding-header.critical { border-left-color: #d32f2f; }
        .finding-header.high { border-left-color: #f44336; }
        .finding-header.medium { border-left-color: #ff9800; }
        .finding-header.low { border-left-color: #2196F3; }
        
        .finding-id {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 5px;
        }
        
        .finding-title {
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
        }
        
        .finding-meta {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .status-badge, .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-badge.passed { background: #e8f5e8; color: #4CAF50; }
        .status-badge.failed { background: #ffebee; color: #f44336; }
        .status-badge.warning { background: #fff3e0; color: #ff9800; }
        
        .severity-badge.critical { background: #ffebee; color: #d32f2f; }
        .severity-badge.high { background: #ffebee; color: #f44336; }
        .severity-badge.medium { background: #fff3e0; color: #ff9800; }
        .severity-badge.low { background: #e3f2fd; color: #2196F3; }
        
        .finding-description {
            color: #666;
            margin-bottom: 15px;
            line-height: 1.5;
        }
        
        .finding-resource {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-family: monospace;
            font-size: 0.9em;
        }
        
        .finding-details {
            border-top: 1px solid #eee;
            padding: 20px;
            background: #fafafa;
        }
        
        .remediation {
            margin-bottom: 20px;
        }
        
        .remediation h4 {
            color: #333;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .remediation p {
            color: #666;
            line-height: 1.5;
        }
        
        .references {
            margin-top: 15px;
        }
        
        .references h4 {
            color: #333;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .references ul {
            list-style: none;
            padding: 0;
        }
        
        .references li {
            margin-bottom: 5px;
        }
        
        .references a {
            color: #667eea;
            text-decoration: none;
            font-size: 0.9em;
        }
        
        .references a:hover {
            text-decoration: underline;
        }
        
        .filter-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .filter-controls {
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .filter-controls label {
            font-weight: bold;
            color: #333;
        }
        
        .filter-controls select, .filter-controls input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9em;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .filter-controls {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .finding-meta {
                flex-direction: column;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Kubernetes Security Scan Report</h1>
            <p>Generated on {{.Timestamp.Format "January 2, 2006 at 3:04 PM"}}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card total">
                <h3>Total Findings</h3>
                <div class="number">{{.Summary.Total}}</div>
            </div>
            <div class="summary-card passed">
                <h3>Passed</h3>
                <div class="number">{{.Summary.Passed}}</div>
            </div>
            <div class="summary-card failed">
                <h3>Failed</h3>
                <div class="number">{{.Summary.Failed}}</div>
            </div>
            <div class="summary-card warnings">
                <h3>Warnings</h3>
                <div class="number">{{.Summary.Warnings}}</div>
            </div>
        </div>
        
        <div class="filter-section">
            <div class="filter-controls">
                <label for="statusFilter">Filter by Status:</label>
                <select id="statusFilter" onchange="filterFindings()">
                    <option value="">All Status</option>
                    <option value="failed">Failed</option>
                    <option value="warning">Warning</option>
                    <option value="passed">Passed</option>
                </select>
                
                <label for="severityFilter">Filter by Severity:</label>
                <select id="severityFilter" onchange="filterFindings()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                
                <label for="standardFilter">Filter by Standard:</label>
                <select id="standardFilter" onchange="filterFindings()">
                    <option value="">All Standards</option>
                    <option value="cis">CIS</option>
                    <option value="nist">NIST</option>
                </select>
            </div>
        </div>
        
        {{range $standard, $findings := .GroupedFindings}}
        <div class="standards-section">
            <div class="standard-header">
                <h2>{{$standard | ToUpper}} Security Standard</h2>
                <p>{{$standard | StandardDescription}}</p>
            </div>
            
            <div class="findings-grid">
                {{range $findings}}
                <div class="finding-card" data-status="{{.Status}}" data-severity="{{.Severity}}" data-standard="{{.Standard}}">
                    <div class="finding-header {{.Severity}}">
                        <div class="finding-id">{{.ID}}</div>
                        <div class="finding-title">{{.Title}}</div>
                        <div class="finding-meta">
                            <span class="status-badge {{.Status}}">{{.Status}}</span>
                            <span class="severity-badge {{.Severity}}">{{.Severity}}</span>
                            <span>Section {{.Section}}</span>
                        </div>
                        <div class="finding-description">{{.Description}}</div>
                        <div class="finding-resource">
                            <strong>Resource:</strong> {{.Resource.Kind}}/{{.Resource.Name}}
                            {{if .Resource.Namespace}}in namespace {{.Resource.Namespace}}{{end}}
                        </div>
                    </div>
                    <div class="finding-details">
                        <div class="remediation">
                            <h4>🔧 Remediation</h4>
                            <p>{{.Remediation}}</p>
                        </div>
                        
                        {{if .References}}
                        <div class="references">
                            <h4>📚 References</h4>
                            <ul>
                                {{range .References}}
                                <li><a href="{{.}}" target="_blank">{{.}}</a></li>
                                {{end}}
                            </ul>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}
        
        <div class="footer">
            <p>Generated by K8s Security Scanner | CIS Kubernetes Benchmark & NIST SP 800-190 Compliance</p>
        </div>
    </div>
    
    <script>
        function filterFindings() {
            const statusFilter = document.getElementById('statusFilter').value;
            const severityFilter = document.getElementById('severityFilter').value;
            const standardFilter = document.getElementById('standardFilter').value;
            
            const findings = document.querySelectorAll('.finding-card');
            
            findings.forEach(finding => {
                const status = finding.getAttribute('data-status');
                const severity = finding.getAttribute('data-severity');
                const standard = finding.getAttribute('data-standard');
                
                let show = true;
                
                if (statusFilter && status !== statusFilter) show = false;
                if (severityFilter && severity !== severityFilter) show = false;
                if (standardFilter && standard !== standardFilter) show = false;
                
                finding.style.display = show ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>`

func (r *reporter) generateHTML(results *scanner.ScanResults, writer io.Writer) error {
	// Group findings by standard
	grouped := r.groupByStandard(results.Findings)
	
	// Sort findings within each standard
	for standard := range grouped {
		sort.Slice(grouped[standard], func(i, j int) bool {
			return grouped[standard][i].ID < grouped[standard][j].ID
		})
	}
	
	// Template data
	data := struct {
		*scanner.ScanResults
		GroupedFindings map[string][]scanner.Finding
	}{
		ScanResults:     results,
		GroupedFindings: grouped,
	}
	
	// Custom template functions
	funcMap := template.FuncMap{
		"ToUpper": strings.ToUpper,
		"StandardDescription": func(standard string) string {
			switch strings.ToLower(standard) {
			case "cis":
				return "Center for Internet Security Kubernetes Benchmark - Industry-standard security configuration guidelines"
			case "nist":
				return "NIST SP 800-190 Application Container Security Guide - Federal security standards for container technologies"
			default:
				return "Security compliance standard"
			}
		},
	}
	
	tmpl, err := template.New("html").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}
	
	return tmpl.Execute(writer, data)
}
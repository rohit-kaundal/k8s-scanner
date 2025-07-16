package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"k8s-scanner/pkg/scanner"
	"gopkg.in/yaml.v3"
)

type Reporter interface {
	Generate(results *scanner.ScanResults) error
}

type reporter struct {
	format     string
	outputFile string
}

func NewReporter(format, outputFile string) Reporter {
	return &reporter{
		format:     format,
		outputFile: outputFile,
	}
}

func (r *reporter) Generate(results *scanner.ScanResults) error {
	writer, err := r.getWriter()
	if err != nil {
		return fmt.Errorf("failed to get writer: %w", err)
	}
	defer r.closeWriter(writer)

	switch r.format {
	case "json":
		return r.generateJSON(results, writer)
	case "yaml":
		return r.generateYAML(results, writer)
	case "text":
		return r.generateText(results, writer)
	case "html":
		return r.generateHTML(results, writer)
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

func (r *reporter) getWriter() (io.Writer, error) {
	if r.outputFile == "" {
		return os.Stdout, nil
	}

	file, err := os.Create(r.outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	return file, nil
}

func (r *reporter) closeWriter(writer io.Writer) {
	if file, ok := writer.(*os.File); ok && file != os.Stdout {
		file.Close()
	}
}

func (r *reporter) generateJSON(results *scanner.ScanResults, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func (r *reporter) generateYAML(results *scanner.ScanResults, writer io.Writer) error {
	encoder := yaml.NewEncoder(writer)
	defer encoder.Close()
	return encoder.Encode(results)
}

func (r *reporter) generateText(results *scanner.ScanResults, writer io.Writer) error {
	// Create color printer
	cp := NewColorPrinter(writer)
	
	// Print enhanced header
	cp.PrintTitle("🔐 KUBERNETES SECURITY SCAN REPORT")
	cp.PrintSeparator("═", 80)
	cp.Printf("\n")
	
	// Print scan metadata
	cp.PrintSubtitle("📅 SCAN METADATA")
	cp.PrintSeparator("─", 40)
	cp.Printf("Scan Time: %s\n", cp.info(results.Timestamp.Format(time.RFC3339)))
	cp.Printf("\n")
	
	// Print colored summary stats
	PrintColoredSummaryStats(results.Summary, cp)
	cp.Printf("\n")
	
	if len(results.Findings) == 0 {
		cp.PrintSuccess("🎉 No findings to report - your cluster is secure!\n")
		return nil
	}
	
	// Print aggregated vulnerability analysis
	agg := AggregateVulnerabilities(results.Findings)
	PrintAggregatedSummary(agg, cp)
	
	return nil
}

func (r *reporter) groupByStandard(findings []scanner.Finding) map[string][]scanner.Finding {
	grouped := make(map[string][]scanner.Finding)
	
	for _, finding := range findings {
		grouped[finding.Standard] = append(grouped[finding.Standard], finding)
	}
	
	return grouped
}

func (r *reporter) printFindingsTable(findings []scanner.Finding, writer io.Writer) {
	w := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	
	fmt.Fprintf(w, "ID\tTitle\tSeverity\tStatus\tResource\n")
	fmt.Fprintf(w, "--\t-----\t--------\t------\t--------\n")
	
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	
	for _, finding := range findings {
		resourceName := finding.Resource.Name
		if finding.Resource.Namespace != "" {
			resourceName = fmt.Sprintf("%s/%s", finding.Resource.Namespace, resourceName)
		}
		
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s/%s\n",
			finding.ID,
			truncateString(finding.Title, 40),
			finding.Severity,
			finding.Status,
			finding.Resource.Kind,
			resourceName)
	}
	
	w.Flush()
}

func (r *reporter) printDetailedFindings(findings []scanner.Finding, writer io.Writer) {
	failedFindings := make([]scanner.Finding, 0)
	warningFindings := make([]scanner.Finding, 0)
	
	for _, finding := range findings {
		if finding.Status == scanner.StatusFailed {
			failedFindings = append(failedFindings, finding)
		} else if finding.Status == scanner.StatusWarning {
			warningFindings = append(warningFindings, finding)
		}
	}
	
	if len(failedFindings) > 0 {
		fmt.Fprintf(writer, "Failed Checks\n")
		fmt.Fprintf(writer, "=============\n\n")
		
		for _, finding := range failedFindings {
			r.printDetailedFinding(finding, writer)
		}
	}
	
	if len(warningFindings) > 0 {
		fmt.Fprintf(writer, "Warnings\n")
		fmt.Fprintf(writer, "========\n\n")
		
		for _, finding := range warningFindings {
			r.printDetailedFinding(finding, writer)
		}
	}
}

func (r *reporter) printDetailedFinding(finding scanner.Finding, writer io.Writer) {
	fmt.Fprintf(writer, "[%s] %s\n", finding.ID, finding.Title)
	fmt.Fprintf(writer, "Standard: %s (Section %s)\n", strings.ToUpper(finding.Standard), finding.Section)
	fmt.Fprintf(writer, "Severity: %s\n", finding.Severity)
	fmt.Fprintf(writer, "Status: %s\n", finding.Status)
	
	if finding.Resource.Namespace != "" {
		fmt.Fprintf(writer, "Resource: %s/%s in namespace %s\n", finding.Resource.Kind, finding.Resource.Name, finding.Resource.Namespace)
	} else {
		fmt.Fprintf(writer, "Resource: %s/%s\n", finding.Resource.Kind, finding.Resource.Name)
	}
	
	fmt.Fprintf(writer, "Description: %s\n", finding.Description)
	fmt.Fprintf(writer, "Remediation: %s\n", finding.Remediation)
	
	if len(finding.References) > 0 {
		fmt.Fprintf(writer, "References:\n")
		for _, ref := range finding.References {
			fmt.Fprintf(writer, "  - %s\n", ref)
		}
	}
	
	fmt.Fprintf(writer, "\n")
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
package report

import (
	"fmt"
	"sort"
	"strings"

	"k8s-scanner/pkg/scanner"
)

// PrintAggregatedSummary prints a comprehensive vulnerability summary with colors
func PrintAggregatedSummary(agg *VulnerabilityAggregation, cp *ColorPrinter) {
	// Print main header
	cp.PrintTitle("🔍 VULNERABILITY ANALYSIS SUMMARY")
	cp.PrintSeparator("═", 80)
	cp.Printf("\n")

	// Print overall statistics
	printOverallStats(agg, cp)
	cp.Printf("\n")

	// Print severity distribution
	printSeverityDistribution(agg, cp)
	cp.Printf("\n")

	// Print standard distribution
	printStandardDistribution(agg, cp)
	cp.Printf("\n")

	// Print top vulnerabilities
	printTopVulnerabilities(agg, cp)
	cp.Printf("\n")

	// Print critical resources
	printCriticalResources(agg, cp)
	cp.Printf("\n")
}

// printOverallStats prints overall vulnerability statistics
func printOverallStats(agg *VulnerabilityAggregation, cp *ColorPrinter) {
	cp.PrintSubtitle("📊 OVERALL STATISTICS")
	cp.PrintSeparator("─", 50)

	totalFailed := len(agg.ByStatus[scanner.StatusFailed])
	totalWarnings := len(agg.ByStatus[scanner.StatusWarning])
	totalPassed := len(agg.ByStatus[scanner.StatusPassed])
	totalFindings := totalFailed + totalWarnings + totalPassed

	cp.Printf("Total Security Checks: %s\n", cp.bold("%d", totalFindings))
	cp.PrintStatus(scanner.StatusPassed, "✅ Passed: %d", totalPassed)
	cp.Printf("\n")
	cp.PrintStatus(scanner.StatusFailed, "❌ Failed: %d", totalFailed)
	cp.Printf("\n")
	cp.PrintStatus(scanner.StatusWarning, "⚠️  Warnings: %d", totalWarnings)
	cp.Printf("\n")

	if totalFindings > 0 {
		passRate := float64(totalPassed) / float64(totalFindings) * 100
		cp.Printf("Pass Rate: ")
		if passRate >= 80 {
			cp.PrintSuccess("%.1f%%", passRate)
		} else if passRate >= 60 {
			cp.PrintWarning("%.1f%%", passRate)
		} else {
			cp.PrintError("%.1f%%", passRate)
		}
		cp.Printf("\n")
	}
}

// printSeverityDistribution prints vulnerability distribution by severity
func printSeverityDistribution(agg *VulnerabilityAggregation, cp *ColorPrinter) {
	cp.PrintSubtitle("🎯 SEVERITY DISTRIBUTION")
	cp.PrintSeparator("─", 50)

	severityStats := agg.GetSeverityStats()
	
	// Sort severities by priority
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
	}

	total := 0
	for _, count := range severityStats {
		total += count
	}

	if total == 0 {
		cp.PrintSuccess("No vulnerabilities found! 🎉\n")
		return
	}

	for _, severity := range severities {
		count := severityStats[severity]
		if count > 0 {
			percentage := float64(count) / float64(total) * 100
			cp.Printf("%s: %d (%.1f%%)\n", cp.SeverityToString(severity), count, percentage)
			
			// Print mini bar chart
			barWidth := 30
			filled := int(percentage / 100 * float64(barWidth))
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
			cp.PrintSeverity(severity, "  [%s]\n", bar)
		}
	}
}

// printStandardDistribution prints vulnerability distribution by standard
func printStandardDistribution(agg *VulnerabilityAggregation, cp *ColorPrinter) {
	cp.PrintSubtitle("📋 STANDARD DISTRIBUTION")
	cp.PrintSeparator("─", 50)

	standardStats := agg.GetStandardStats()
	
	total := 0
	for _, count := range standardStats {
		total += count
	}

	if total == 0 {
		cp.PrintSuccess("No standard violations found! 🎉\n")
		return
	}

	// Sort standards by count
	type standardCount struct {
		name  string
		count int
	}
	
	standards := make([]standardCount, 0)
	for standard, count := range standardStats {
		if count > 0 {
			standards = append(standards, standardCount{standard, count})
		}
	}
	
	sort.Slice(standards, func(i, j int) bool {
		return standards[i].count > standards[j].count
	})

	for _, std := range standards {
		percentage := float64(std.count) / float64(total) * 100
		cp.Printf("📖 %s: %s (%s)\n", 
			cp.bold(std.name), 
			cp.info("%d", std.count), 
			cp.dim("%.1f%%", percentage))
		
		// Print mini bar chart
		barWidth := 25
		filled := int(percentage / 100 * float64(barWidth))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		cp.PrintInfo("  [%s]\n", bar)
	}
}

// printTopVulnerabilities prints the most common vulnerabilities
func printTopVulnerabilities(agg *VulnerabilityAggregation, cp *ColorPrinter) {
	cp.PrintSubtitle("🔥 TOP VULNERABILITIES")
	cp.PrintSeparator("─", 50)

	if len(agg.TopVulnerabilities) == 0 {
		cp.PrintSuccess("No vulnerabilities found! 🎉\n")
		return
	}

	for i, vuln := range agg.TopVulnerabilities {
		if i >= 5 { // Show top 5
			break
		}
		
		cp.Printf("%d. %s\n", i+1, cp.bold(vuln.Title))
		cp.Printf("   Standard: %s | ", cp.info(vuln.Standard))
		cp.Printf("Severity: %s | ", cp.SeverityToString(vuln.Severity))
		cp.Printf("Count: %s\n", cp.failed("%d", vuln.Count))
		
		// Show affected resources (up to 3)
		resourceCount := len(vuln.Resources)
		if resourceCount > 0 {
			cp.PrintDim("   Affected: ")
			for j, resource := range vuln.Resources {
				if j >= 3 {
					cp.PrintDim("... and %d more", resourceCount-3)
					break
				}
				if j > 0 {
					cp.PrintDim(", ")
				}
				cp.PrintDim(resource)
			}
			cp.Printf("\n")
		}
		
		// Show truncated description
		if len(vuln.Description) > 100 {
			cp.PrintDim("   %s...\n", vuln.Description[:100])
		} else {
			cp.PrintDim("   %s\n", vuln.Description)
		}
		cp.Printf("\n")
	}
}

// printCriticalResources prints resources with the most vulnerabilities
func printCriticalResources(agg *VulnerabilityAggregation, cp *ColorPrinter) {
	cp.PrintSubtitle("⚠️  CRITICAL RESOURCES")
	cp.PrintSeparator("─", 50)

	if len(agg.CriticalResources) == 0 {
		cp.PrintSuccess("No critical resources found! 🎉\n")
		return
	}

	for i, resource := range agg.CriticalResources {
		if i >= 5 { // Show top 5
			break
		}
		
		resourceName := resource.Resource.Name
		if resource.Resource.Namespace != "" {
			resourceName = fmt.Sprintf("%s/%s", resource.Resource.Namespace, resourceName)
		}
		
		cp.Printf("%d. %s/%s\n", i+1, cp.bold(resource.Resource.Kind), cp.info(resourceName))
		cp.Printf("   Total Issues: %s\n", cp.failed("%d", resource.TotalCount))
		
		// Show severity breakdown
		cp.PrintDim("   Severity Breakdown: ")
		first := true
		for _, severity := range []scanner.Severity{
			scanner.SeverityCritical,
			scanner.SeverityHigh,
			scanner.SeverityMedium,
			scanner.SeverityLow,
		} {
			if count := resource.SeverityCount[severity]; count > 0 {
				if !first {
					cp.PrintDim(" | ")
				}
				cp.PrintSeverity(severity, "%s: %d", strings.ToUpper(string(severity)), count)
				first = false
			}
		}
		cp.Printf("\n")
		
		// Show top issues for this resource
		cp.PrintDim("   Top Issues: ")
		issueCount := 0
		for _, finding := range resource.Findings {
			if issueCount >= 2 { // Show max 2 issues
				break
			}
			if issueCount > 0 {
				cp.PrintDim(", ")
			}
			cp.PrintDim(finding.Title)
			issueCount++
		}
		if len(resource.Findings) > 2 {
			cp.PrintDim("... and %d more", len(resource.Findings)-2)
		}
		cp.Printf("\n\n")
	}
}

// PrintColoredSummaryStats prints a compact colored summary
func PrintColoredSummaryStats(summary scanner.Summary, cp *ColorPrinter) {
	cp.PrintTitle("📋 SCAN SUMMARY")
	cp.PrintSeparator("─", 40)
	
	total := summary.Total
	if total == 0 {
		cp.PrintInfo("No checks performed.\n")
		return
	}
	
	cp.Printf("Total Checks: %s\n", cp.bold("%d", total))
	
	// Print with colors and icons
	cp.PrintSuccess("✅ Passed: %d (%.1f%%)\n", 
		summary.Passed, 
		float64(summary.Passed)/float64(total)*100)
	
	cp.PrintError("❌ Failed: %d (%.1f%%)\n", 
		summary.Failed, 
		float64(summary.Failed)/float64(total)*100)
	
	cp.PrintWarning("⚠️  Warnings: %d (%.1f%%)\n", 
		summary.Warnings, 
		float64(summary.Warnings)/float64(total)*100)
	
	cp.Printf("\n")
	
	// Overall health indicator
	if summary.Failed == 0 && summary.Warnings == 0 {
		cp.PrintSuccess("🎉 All checks passed! Your cluster is secure.\n")
	} else if summary.Failed == 0 {
		cp.PrintWarning("⚠️  Some warnings found. Consider reviewing them.\n")
	} else {
		cp.PrintError("🚨 Critical issues found! Immediate attention required.\n")
	}
}
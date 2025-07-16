package report

import (
	"fmt"
	"sort"
	"strings"

	"k8s-scanner/pkg/scanner"
)

// VulnerabilityAggregation represents aggregated vulnerability data
type VulnerabilityAggregation struct {
	BySeverity       map[scanner.Severity][]scanner.Finding
	ByStatus         map[scanner.Status][]scanner.Finding
	ByStandard       map[string][]scanner.Finding
	ByResource       map[string][]scanner.Finding
	TopVulnerabilities []VulnerabilityCount
	CriticalResources []ResourceVulnerability
}

// VulnerabilityCount represents a vulnerability type and its occurrence count
type VulnerabilityCount struct {
	Title       string
	Count       int
	Severity    scanner.Severity
	Standard    string
	Resources   []string
	Description string
}

// ResourceVulnerability represents a resource with its vulnerabilities
type ResourceVulnerability struct {
	Resource     scanner.Resource
	Findings     []scanner.Finding
	SeverityCount map[scanner.Severity]int
	TotalCount   int
}

// AggregateVulnerabilities creates comprehensive vulnerability aggregation
func AggregateVulnerabilities(findings []scanner.Finding) *VulnerabilityAggregation {
	agg := &VulnerabilityAggregation{
		BySeverity:        make(map[scanner.Severity][]scanner.Finding),
		ByStatus:          make(map[scanner.Status][]scanner.Finding),
		ByStandard:        make(map[string][]scanner.Finding),
		ByResource:        make(map[string][]scanner.Finding),
		TopVulnerabilities: make([]VulnerabilityCount, 0),
		CriticalResources:  make([]ResourceVulnerability, 0),
	}

	// Group by different categories
	for _, finding := range findings {
		// By severity
		agg.BySeverity[finding.Severity] = append(agg.BySeverity[finding.Severity], finding)
		
		// By status
		agg.ByStatus[finding.Status] = append(agg.ByStatus[finding.Status], finding)
		
		// By standard
		agg.ByStandard[finding.Standard] = append(agg.ByStandard[finding.Standard], finding)
		
		// By resource
		resourceKey := fmt.Sprintf("%s/%s", finding.Resource.Kind, finding.Resource.Name)
		if finding.Resource.Namespace != "" {
			resourceKey = fmt.Sprintf("%s/%s", finding.Resource.Namespace, resourceKey)
		}
		agg.ByResource[resourceKey] = append(agg.ByResource[resourceKey], finding)
	}

	// Calculate top vulnerabilities
	agg.TopVulnerabilities = calculateTopVulnerabilities(findings)
	
	// Calculate critical resources
	agg.CriticalResources = calculateCriticalResources(agg.ByResource)

	return agg
}

// calculateTopVulnerabilities identifies the most common vulnerability types
func calculateTopVulnerabilities(findings []scanner.Finding) []VulnerabilityCount {
	vulnMap := make(map[string]*VulnerabilityCount)
	
	for _, finding := range findings {
		if finding.Status == scanner.StatusFailed || finding.Status == scanner.StatusWarning {
			key := fmt.Sprintf("%s|%s", finding.Title, finding.Standard)
			
			if vuln, exists := vulnMap[key]; exists {
				vuln.Count++
				// Add resource if not already present
				resourceName := finding.Resource.Name
				if finding.Resource.Namespace != "" {
					resourceName = fmt.Sprintf("%s/%s", finding.Resource.Namespace, resourceName)
				}
				resourceKey := fmt.Sprintf("%s/%s", finding.Resource.Kind, resourceName)
				
				found := false
				for _, res := range vuln.Resources {
					if res == resourceKey {
						found = true
						break
					}
				}
				if !found {
					vuln.Resources = append(vuln.Resources, resourceKey)
				}
			} else {
				resourceName := finding.Resource.Name
				if finding.Resource.Namespace != "" {
					resourceName = fmt.Sprintf("%s/%s", finding.Resource.Namespace, resourceName)
				}
				resourceKey := fmt.Sprintf("%s/%s", finding.Resource.Kind, resourceName)
				
				vulnMap[key] = &VulnerabilityCount{
					Title:       finding.Title,
					Count:       1,
					Severity:    finding.Severity,
					Standard:    finding.Standard,
					Resources:   []string{resourceKey},
					Description: finding.Description,
				}
			}
		}
	}
	
	// Convert to slice and sort by count
	vulns := make([]VulnerabilityCount, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		vulns = append(vulns, *vuln)
	}
	
	sort.Slice(vulns, func(i, j int) bool {
		// Sort by count first, then by severity
		if vulns[i].Count != vulns[j].Count {
			return vulns[i].Count > vulns[j].Count
		}
		return getSeverityPriority(vulns[i].Severity) > getSeverityPriority(vulns[j].Severity)
	})
	
	// Return top 10 vulnerabilities
	if len(vulns) > 10 {
		return vulns[:10]
	}
	return vulns
}

// calculateCriticalResources identifies resources with the most vulnerabilities
func calculateCriticalResources(byResource map[string][]scanner.Finding) []ResourceVulnerability {
	resources := make([]ResourceVulnerability, 0)
	
	for _, findings := range byResource {
		if len(findings) == 0 {
			continue
		}
		
		// Count failures and warnings only
		failedOrWarning := make([]scanner.Finding, 0)
		severityCount := make(map[scanner.Severity]int)
		
		for _, finding := range findings {
			if finding.Status == scanner.StatusFailed || finding.Status == scanner.StatusWarning {
				failedOrWarning = append(failedOrWarning, finding)
				severityCount[finding.Severity]++
			}
		}
		
		if len(failedOrWarning) > 0 {
			resources = append(resources, ResourceVulnerability{
				Resource:      findings[0].Resource, // All findings have the same resource
				Findings:      failedOrWarning,
				SeverityCount: severityCount,
				TotalCount:    len(failedOrWarning),
			})
		}
	}
	
	// Sort by total count and severity
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].TotalCount != resources[j].TotalCount {
			return resources[i].TotalCount > resources[j].TotalCount
		}
		// If equal count, prioritize by highest severity
		return getMaxSeverityPriority(resources[i].SeverityCount) > getMaxSeverityPriority(resources[j].SeverityCount)
	})
	
	// Return top 10 critical resources
	if len(resources) > 10 {
		return resources[:10]
	}
	return resources
}

// getSeverityPriority returns numeric priority for sorting
func getSeverityPriority(severity scanner.Severity) int {
	switch severity {
	case scanner.SeverityCritical:
		return 4
	case scanner.SeverityHigh:
		return 3
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityLow:
		return 1
	default:
		return 0
	}
}

// getMaxSeverityPriority returns the highest severity priority from a count map
func getMaxSeverityPriority(severityCount map[scanner.Severity]int) int {
	maxPriority := 0
	for severity, count := range severityCount {
		if count > 0 {
			priority := getSeverityPriority(severity)
			if priority > maxPriority {
				maxPriority = priority
			}
		}
	}
	return maxPriority
}

// GetSeverityStats returns statistics about severity distribution
func (agg *VulnerabilityAggregation) GetSeverityStats() map[scanner.Severity]int {
	stats := make(map[scanner.Severity]int)
	
	for severity, findings := range agg.BySeverity {
		count := 0
		for _, finding := range findings {
			if finding.Status == scanner.StatusFailed || finding.Status == scanner.StatusWarning {
				count++
			}
		}
		stats[severity] = count
	}
	
	return stats
}

// GetStandardStats returns statistics about standard distribution
func (agg *VulnerabilityAggregation) GetStandardStats() map[string]int {
	stats := make(map[string]int)
	
	for standard, findings := range agg.ByStandard {
		count := 0
		for _, finding := range findings {
			if finding.Status == scanner.StatusFailed || finding.Status == scanner.StatusWarning {
				count++
			}
		}
		stats[strings.ToUpper(standard)] = count
	}
	
	return stats
}
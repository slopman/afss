package findings_processor

import (
	"fmt"
	"strings"
)

// BasicCorrelator implements CorrelationEngine
type BasicCorrelator struct{}

// NewBasicCorrelator creates a new basic correlator
func NewBasicCorrelator() *BasicCorrelator {
	return &BasicCorrelator{}
}

// Correlate finds relationships between findings
func (c *BasicCorrelator) Correlate(findings []NormalizedFinding) ([]Correlation, error) {
	var correlations []Correlation

	// Find same vulnerability correlations
	sameVulnCorrelations := c.findSameVulnerabilities(findings)
	correlations = append(correlations, sameVulnCorrelations...)

	// Find same file correlations
	sameFileCorrelations := c.findSameFileFindings(findings)
	correlations = append(correlations, sameFileCorrelations...)

	// Find related vulnerability correlations
	relatedCorrelations := c.findRelatedVulnerabilities(findings)
	correlations = append(correlations, relatedCorrelations...)

	// Find same package correlations
	samePackageCorrelations := c.findSamePackageFindings(findings)
	correlations = append(correlations, samePackageCorrelations...)

	// Find dependency chain correlations
	dependencyCorrelations := c.findDependencyChainCorrelations(findings)
	correlations = append(correlations, dependencyCorrelations...)

	return correlations, nil
}

// findSameVulnerabilities finds findings that represent the same vulnerability
func (c *BasicCorrelator) findSameVulnerabilities(findings []NormalizedFinding) []Correlation {
	var correlations []Correlation

	// Group by CWE + normalized code hash
	vulnGroups := make(map[string][]NormalizedFinding)

	for _, finding := range findings {
		if len(finding.CWE) == 0 {
			continue
		}

		// Use first CWE and file:line as key
		key := fmt.Sprintf("%s:%s:%d", finding.CWE[0], finding.File, finding.Line)
		vulnGroups[key] = append(vulnGroups[key], finding)
	}

	// Create correlations for groups with multiple findings
	for key, group := range vulnGroups {
		if len(group) > 1 {
			findingIDs := make([]string, len(group))
			for i, f := range group {
				findingIDs[i] = f.ID
			}

			correlation := Correlation{
				ID:          fmt.Sprintf("same_vuln_%s", key),
				Type:        SameVulnerability,
				Findings:    findingIDs,
				Strength:    0.9, // High confidence for same CWE + location
				Description: fmt.Sprintf("Same vulnerability detected by %d tools", len(group)),
				Metadata: map[string]interface{}{
					"cwe":        group[0].CWE[0],
					"file":       group[0].File,
					"line":       group[0].Line,
					"tools":      c.extractTools(group),
				},
			}
			correlations = append(correlations, correlation)
		}
	}

	return correlations
}

// findSameFileFindings finds findings in the same file
func (c *BasicCorrelator) findSameFileFindings(findings []NormalizedFinding) []Correlation {
	var correlations []Correlation

	// Group by file
	fileGroups := make(map[string][]NormalizedFinding)

	for _, finding := range findings {
		fileGroups[finding.File] = append(fileGroups[finding.File], finding)
	}

	// Create correlations for files with multiple findings
	for file, group := range fileGroups {
		if len(group) > 1 {
			findingIDs := make([]string, len(group))
			for i, f := range group {
				findingIDs[i] = f.ID
			}

			correlation := Correlation{
				ID:          fmt.Sprintf("same_file_%s", c.sanitizeFilename(file)),
				Type:        SameFile,
				Findings:    findingIDs,
				Strength:    0.7, // Medium confidence for same file
				Description: fmt.Sprintf("%d findings in same file", len(group)),
				Metadata: map[string]interface{}{
					"file":       file,
					"finding_count": len(group),
					"tools":      c.extractTools(group),
				},
			}
			correlations = append(correlations, correlation)
		}
	}

	return correlations
}

// findRelatedVulnerabilities finds related vulnerabilities (same CWE, different locations)
func (c *BasicCorrelator) findRelatedVulnerabilities(findings []NormalizedFinding) []Correlation {
	var correlations []Correlation

	// Group by CWE
	cweGroups := make(map[string][]NormalizedFinding)

	for _, finding := range findings {
		for _, cwe := range finding.CWE {
			cweGroups[cwe] = append(cweGroups[cwe], finding)
		}
	}

	// Create correlations for CWE groups with multiple findings
	for cwe, group := range cweGroups {
		if len(group) > 1 {
			// Remove duplicates by ID
			uniqueFindings := c.removeDuplicateFindings(group)

			if len(uniqueFindings) > 1 {
				findingIDs := make([]string, len(uniqueFindings))
				for i, f := range uniqueFindings {
					findingIDs[i] = f.ID
				}

				correlation := Correlation{
					ID:          fmt.Sprintf("related_cwe_%s", cwe),
					Type:        RelatedVulnerability,
					Findings:    findingIDs,
					Strength:    0.6, // Medium confidence for same CWE
					Description: fmt.Sprintf("Related vulnerabilities with CWE-%s", cwe),
					Metadata: map[string]interface{}{
						"cwe":        cwe,
						"finding_count": len(uniqueFindings),
						"tools":      c.extractTools(uniqueFindings),
					},
				}
				correlations = append(correlations, correlation)
			}
		}
	}

	return correlations
}

// findSamePackageFindings finds findings in the same package (directory)
func (c *BasicCorrelator) findSamePackageFindings(findings []NormalizedFinding) []Correlation {
	var correlations []Correlation

	// Group by package (directory)
	packageGroups := make(map[string][]NormalizedFinding)

	for _, finding := range findings {
		if finding.File == "unknown" || finding.File == "" {
			continue
		}

		pkg := c.extractPackageName(finding.File)
		if pkg != "" && pkg != "." {
			packageGroups[pkg] = append(packageGroups[pkg], finding)
		}
	}

	// Create correlations for packages with multiple findings
	for pkg, group := range packageGroups {
		if len(group) > 1 {
			findingIDs := make([]string, len(group))
			for i, f := range group {
				findingIDs[i] = f.ID
			}

			correlation := Correlation{
				ID:          fmt.Sprintf("same_package_%s", c.sanitizeFilename(pkg)),
				Type:        SamePackage,
				Findings:    findingIDs,
				Strength:    0.5, // Lower confidence for just being in the same package
				Description: fmt.Sprintf("%d findings in same package: %s", len(group), pkg),
				Metadata: map[string]interface{}{
					"package":       pkg,
					"finding_count": len(group),
					"tools":         c.extractTools(group),
				},
			}
			correlations = append(correlations, correlation)
		}
	}

	return correlations
}

// findDependencyChainCorrelations finds related dependency vulnerabilities
func (c *BasicCorrelator) findDependencyChainCorrelations(findings []NormalizedFinding) []Correlation {
	var correlations []Correlation

	// Group by package name (for dependency tools)
	depGroups := make(map[string][]NormalizedFinding)

	for _, finding := range findings {
		if finding.Category != VulnFinding {
			continue
		}

		// Try to extract package name from RawData or File
		pkgName := ""
		if val, ok := finding.RawData["PackageName"].(string); ok {
			pkgName = val
		} else if val, ok := finding.RawData["package_name"].(string); ok {
			pkgName = val
		} else if val, ok := finding.RawData["package"].(string); ok {
			pkgName = val
		}

		if pkgName != "" {
			depGroups[pkgName] = append(depGroups[pkgName], finding)
		}
	}

	// Create correlations for packages with multiple vulnerabilities
	for pkgName, group := range depGroups {
		if len(group) > 1 {
			findingIDs := make([]string, len(group))
			for i, f := range group {
				findingIDs[i] = f.ID
			}

			correlation := Correlation{
				ID:          fmt.Sprintf("dependency_chain_%s", pkgName),
				Type:        DependencyChain,
				Findings:    findingIDs,
				Strength:    0.8, // High confidence for same package
				Description: fmt.Sprintf("Multiple vulnerabilities found in dependency: %s", pkgName),
				Metadata: map[string]interface{}{
					"package_name":  pkgName,
					"finding_count": len(group),
					"tools":         c.extractTools(group),
				},
			}
			correlations = append(correlations, correlation)
		}
	}

	return correlations
}

// Helper functions

func (c *BasicCorrelator) extractTools(findings []NormalizedFinding) []string {
	tools := make(map[string]bool)
	for _, f := range findings {
		tools[f.Tool] = true
	}

	toolList := make([]string, 0, len(tools))
	for tool := range tools {
		toolList = append(toolList, tool)
	}
	return toolList
}

func (c *BasicCorrelator) removeDuplicateFindings(findings []NormalizedFinding) []NormalizedFinding {
	seen := make(map[string]bool)
	var unique []NormalizedFinding

	for _, f := range findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			unique = append(unique, f)
		}
	}

	return unique
}

func (c *BasicCorrelator) sanitizeFilename(filename string) string {
	// Replace path separators and special characters for ID generation
	sanitized := strings.ReplaceAll(filename, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, "\\", "_")
	sanitized = strings.ReplaceAll(sanitized, ".", "_")
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")
	return sanitized
}

func (c *BasicCorrelator) extractPackageName(filePath string) string {
	// Simple package name extraction from file path (directory)
	parts := strings.Split(filePath, "/")
	if len(parts) <= 1 {
		return "."
	}
	return strings.Join(parts[:len(parts)-1], "/")
}
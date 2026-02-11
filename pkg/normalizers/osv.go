package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// OSVNormalizer handles OSV vulnerability scanner output
type OSVNormalizer struct{}

// NewOSVNormalizer creates a new OSV normalizer
func NewOSVNormalizer() *OSVNormalizer {
	return &OSVNormalizer{}
}

// ToolName returns the tool name
func (n *OSVNormalizer) ToolName() string {
	return "osv"
}

// CanHandle checks if this normalizer can handle the given data
func (n *OSVNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	if _, exists := data["results"]; exists {
		results, ok := data["results"].([]interface{})
		if ok && len(results) > 0 {
			first, ok := results[0].(map[string]interface{})
			if ok {
				if _, hasSource := first["source"]; hasSource {
					return true
				}
			}
		}
	}

	return false
}

// Normalize converts OSV output to normalized findings
func (n *OSVNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Summary  string `json:"summary"`
					Details  string `json:"details"`
					Modified string `json:"modified"`
					Severity []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					} `json:"severity"`
					DatabaseSpecific struct {
						CWEIDs   []string `json:"cwe_ids"`
						Severity string   `json:"severity"`
					} `json:"database_specific"`
					References []struct {
						Type string `json:"type"`
						URL  string `json:"url"`
					} `json:"references"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse osv JSON: %w", err)
	}

	var normalized []findings_processor.NormalizedFinding

	for _, result := range data.Results {
		filePath := result.Source.Path
		// Strip possible local prefix if needed, but for now keep as is
		
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				finding := findings_processor.NormalizedFinding{
					ID:          fmt.Sprintf("osv_%s", vuln.ID),
					Title:       vuln.Summary,
					Description: vuln.Details,
					Tool:        "osv",
					RuleID:      vuln.ID,
					File:        filePath,
					Category:    findings_processor.VulnFinding,
					Confidence:  findings_processor.Certain,
					CWE:         vuln.DatabaseSpecific.CWEIDs,
					RawData: map[string]interface{}{
						"package_name":    pkg.Package.Name,
						"package_version": pkg.Package.Version,
						"ecosystem":       pkg.Package.Ecosystem,
						"modified":        vuln.Modified,
					},
				}

				if finding.Title == "" {
					finding.Title = fmt.Sprintf("Vulnerability in %s", pkg.Package.Name)
				}

				// Determine severity
				if vuln.DatabaseSpecific.Severity != "" {
					finding.Severity = n.normalizeSeverity(vuln.DatabaseSpecific.Severity)
				} else if len(vuln.Severity) > 0 {
					// Try to parse CVSS score
					finding.Severity = n.parseCVSSSeverity(vuln.Severity[0].Score)
				} else {
					finding.Severity = findings_processor.Medium
				}

				// Add references
				var refs []string
				for _, r := range vuln.References {
					refs = append(refs, r.URL)
				}
				finding.References = refs

				normalized = append(normalized, finding)
			}
		}
	}

	return normalized, nil
}

// normalizeSeverity converts OSV-specific severity to standard levels
func (n *OSVNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return findings_processor.Critical
	case "HIGH":
		return findings_processor.High
	case "MEDIUM", "MODERATE":
		return findings_processor.Medium
	case "LOW":
		return findings_processor.Low
	default:
		return findings_processor.Medium
	}
}

// parseCVSSSeverity tries to map CVSS score string (e.g., "CVSS:3.1/...") to severity level
func (n *OSVNormalizer) parseCVSSSeverity(scoreStr string) findings_processor.SeverityLevel {
	// This is a very basic mapping. In a real scenario, we'd parse the score properly.
	// Often it's easier to look for common patterns or just default to Medium.
	if strings.Contains(scoreStr, "/S:C") || strings.Contains(scoreStr, "/AV:N") {
		return findings_processor.High
	}
	return findings_processor.Medium
}

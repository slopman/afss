package normalizers

import (
	"encoding/json"
	"fmt"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// TrivyNormalizer handles Trivy vulnerability scanner output
type TrivyNormalizer struct{}

// NewTrivyNormalizer creates a new Trivy normalizer
func NewTrivyNormalizer() *TrivyNormalizer {
	return &TrivyNormalizer{}
}

// ToolName returns the tool name
func (n *TrivyNormalizer) ToolName() string {
	return "trivy"
}

// CanHandle checks if this normalizer can handle the given data
func (n *TrivyNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	// Trivy has "Results" array and "SchemaVersion" field
	_, hasResults := data["Results"]
	_, hasSchema := data["SchemaVersion"]

	if !hasResults || !hasSchema {
		return false
	}

	// Check if Results contains objects with Vulnerabilities
	results, ok := data["Results"].([]interface{})
	if !ok || len(results) == 0 {
		return false
	}

	firstResult, ok := results[0].(map[string]interface{})
	if !ok {
		return false
	}

	_, hasVulnerabilities := firstResult["Vulnerabilities"]
	return hasVulnerabilities
}

// Normalize converts Trivy output to normalized findings
func (n *TrivyNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON: %w", err)
	}

	results, ok := data["Results"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("trivy Results not found or not an array")
	}

	var normalized []findings_processor.NormalizedFinding

	for _, result := range results {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		vulnerabilities, exists := resultMap["Vulnerabilities"]
		if !exists {
			continue
		}

		vulnArray, ok := vulnerabilities.([]interface{})
		if !ok {
			continue
		}

		for _, vuln := range vulnArray {
			vulnMap, ok := vuln.(map[string]interface{})
			if !ok {
				continue
			}

			finding, err := n.normalizeSingleVulnerability(vulnMap, resultMap)
			if err != nil {
				// Skip invalid results but continue processing
				continue
			}

			normalized = append(normalized, finding)
		}
	}

	return normalized, nil
}

// normalizeSingleVulnerability converts a single Trivy vulnerability to normalized finding
func (n *TrivyNormalizer) normalizeSingleVulnerability(vuln map[string]interface{}, result map[string]interface{}) (findings_processor.NormalizedFinding, error) {
	finding := findings_processor.NormalizedFinding{
		RawData: vuln,
	}

	// Extract basic fields
	finding.Title = n.extractString(vuln, []string{"Title", "VulnerabilityID"}, "Vulnerability detected")
	finding.Description = n.extractString(vuln, []string{"Description"}, "")
	finding.RuleID = n.extractString(vuln, []string{"VulnerabilityID"}, "unknown")
	finding.Tool = "trivy"

	// Extract package info for file-like field
	if pkgName, exists := vuln["PkgName"]; exists {
		if pkgStr, ok := pkgName.(string); ok {
			finding.File = pkgStr
		}
	}

	// Normalize severity
	severityStr := n.extractString(vuln, []string{"Severity"}, "UNKNOWN")
	finding.Severity = n.normalizeSeverity(severityStr)

	// High confidence for Trivy vulnerabilities
	finding.Confidence = findings_processor.Certain

	// Category is vulnerability
	finding.Category = findings_processor.VulnFinding

	// Extract CWE
	finding.CWE = n.extractCWE(vuln)

	// Extract CVSS score
	finding.CVSS = n.extractCVSS(vuln)

	// Generate ID
	finding.ID = n.generateID(finding)

	return finding, nil
}

// normalizeSeverity converts Trivy severity to standard levels
func (n *TrivyNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch sev {
	case "CRITICAL":
		return findings_processor.Critical
	case "HIGH":
		return findings_processor.High
	case "MEDIUM":
		return findings_processor.Medium
	case "LOW":
		return findings_processor.Low
	default:
		return findings_processor.Info
	}
}

// extractCWE extracts CWE IDs from Trivy vulnerability
func (n *TrivyNormalizer) extractCWE(vuln map[string]interface{}) []string {
	var cwe []string

	if cweIDs, exists := vuln["CweIDs"]; exists {
		if cweArray, ok := cweIDs.([]interface{}); ok {
			for _, cweID := range cweArray {
				if cweStr, ok := cweID.(string); ok {
					cwe = append(cwe, cweStr)
				}
			}
		}
	}

	return cwe
}

// extractCVSS extracts CVSS score from Trivy vulnerability
func (n *TrivyNormalizer) extractCVSS(vuln map[string]interface{}) *findings_processor.CVSSScore {
	if cvss, exists := vuln["CVSS"]; exists {
		if cvssMap, ok := cvss.(map[string]interface{}); ok {
			// Try to get ghsa CVSS first (most common)
			if ghsa, exists := cvssMap["ghsa"]; exists {
				if ghsaMap, ok := ghsa.(map[string]interface{}); ok {
					if score, exists := ghsaMap["V3Score"]; exists {
						if scoreFloat, ok := score.(float64); ok {
							return &findings_processor.CVSSScore{
								Version:   "3.1",
								BaseScore: scoreFloat,
								Severity:  n.scoreToSeverity(scoreFloat),
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// scoreToSeverity converts CVSS score to severity string
func (n *TrivyNormalizer) scoreToSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 0.1 {
		return "LOW"
	}
	return "NONE"
}

// generateID generates a unique ID for the finding
func (n *TrivyNormalizer) generateID(finding findings_processor.NormalizedFinding) string {
	return fmt.Sprintf("trivy_%s_%s", finding.File, finding.RuleID)
}

// Helper methods
func (n *TrivyNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}
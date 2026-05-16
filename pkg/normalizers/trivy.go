package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

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

// trivyExtractResults returns the Trivy "Results" array (any key casing).
// Trivy 0.69+ may omit "Results" entirely when there are zero findings; in that case
// returns an empty slice if the JSON still looks like a Trivy report envelope.
func trivyExtractResults(data map[string]interface{}) ([]interface{}, error) {
	for k, v := range data {
		if !strings.EqualFold(k, "Results") {
			continue
		}
		if v == nil {
			return []interface{}{}, nil
		}
		arr, ok := v.([]interface{})
		if !ok {
			return nil, fmt.Errorf("trivy Results is not an array")
		}
		return arr, nil
	}
	if trivyIsReportEnvelope(data) {
		return []interface{}{}, nil
	}
	return nil, fmt.Errorf("trivy Results not found or not an array")
}

// trivyIsReportEnvelope detects a Trivy JSON report without requiring a Results key.
func trivyIsReportEnvelope(data map[string]interface{}) bool {
	if trivyHasSchemaVersion(data) {
		return true
	}
	for k := range data {
		if strings.EqualFold(k, "ArtifactName") || strings.EqualFold(k, "ArtifactType") {
			return true
		}
	}
	return false
}

func trivyHasSchemaVersion(data map[string]interface{}) bool {
	for k := range data {
		if strings.EqualFold(k, "SchemaVersion") {
			return true
		}
	}
	return false
}

// CanHandle checks if this normalizer can handle the given data
func (n *TrivyNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}
	_, err := trivyExtractResults(data)
	return err == nil
}

// Normalize converts Trivy output to normalized findings
func (n *TrivyNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON: %w", err)
	}

	results, err := trivyExtractResults(data)
	if err != nil {
		return nil, err
	}

	var normalized []findings_processor.NormalizedFinding

	for _, result := range results {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		if vulnerabilities, exists := resultMap["Vulnerabilities"]; exists {
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
					continue
				}

				normalized = append(normalized, finding)
			}
		}

		if secrets, exists := resultMap["Secrets"]; exists {
			secretArray, ok := secrets.([]interface{})
			if !ok {
				continue
			}
			for _, sec := range secretArray {
				secMap, ok := sec.(map[string]interface{})
				if !ok {
					continue
				}
				finding := n.normalizeTrivySecret(secMap, resultMap)
				normalized = append(normalized, finding)
			}
		}

		if misconfigs, exists := resultMap["Misconfigurations"]; exists {
			misArray, ok := misconfigs.([]interface{})
			if !ok {
				continue
			}
			for _, mc := range misArray {
				mcMap, ok := mc.(map[string]interface{})
				if !ok {
					continue
				}
				finding := n.normalizeTrivyMisconfig(mcMap, resultMap)
				normalized = append(normalized, finding)
			}
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

func (n *TrivyNormalizer) normalizeTrivySecret(sec map[string]interface{}, result map[string]interface{}) findings_processor.NormalizedFinding {
	finding := findings_processor.NormalizedFinding{RawData: sec}
	finding.Title = n.extractString(sec, []string{"Title", "RuleID"}, "Secret")
	finding.Description = n.extractString(sec, []string{"Title", "Match"}, "")
	finding.RuleID = n.extractString(sec, []string{"RuleID", "ID"}, "unknown")
	finding.File = n.extractString(result, []string{"Target"}, "unknown")
	finding.Line = n.extractInt(sec, []string{"StartLine", "Line"}, 0)
	severityStr := n.extractString(sec, []string{"Severity"}, "HIGH")
	finding.Severity = n.normalizeSeverity(severityStr)
	finding.Confidence = findings_processor.Certain
	finding.Category = findings_processor.SecretFinding
	finding.Tool = "trivy"
	finding.ID = fmt.Sprintf("trivy_secret_%s_%s_%d", finding.File, finding.RuleID, finding.Line)
	return finding
}

func (n *TrivyNormalizer) normalizeTrivyMisconfig(mc map[string]interface{}, result map[string]interface{}) findings_processor.NormalizedFinding {
	finding := findings_processor.NormalizedFinding{RawData: mc}
	finding.Title = n.extractString(mc, []string{"Title", "ID"}, "Misconfiguration")
	finding.Description = n.extractString(mc, []string{"Description", "Message"}, "")
	finding.RuleID = n.extractString(mc, []string{"ID", "AVDID"}, "unknown")
	finding.File = n.extractString(result, []string{"Target"}, "unknown")
	finding.Line = n.extractInt(mc, []string{"StartLine", "Line"}, 0)
	severityStr := n.extractString(mc, []string{"Severity"}, "UNKNOWN")
	finding.Severity = n.normalizeSeverity(severityStr)
	finding.Confidence = findings_processor.Certain
	finding.Category = findings_processor.ConfigFinding
	finding.Tool = "trivy"
	finding.ID = fmt.Sprintf("trivy_misconfig_%s_%s_%d", finding.File, finding.RuleID, finding.Line)
	return finding
}

// normalizeSeverity converts Trivy severity to standard levels
func (n *TrivyNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
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

func (n *TrivyNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			switch v := val.(type) {
			case float64:
				return int(v)
			case json.Number:
				if i, err := v.Int64(); err == nil {
					return int(i)
				}
			}
		}
	}
	return defaultValue
}
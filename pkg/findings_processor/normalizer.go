package findings_processor

import (
	"crypto/md5"
	"fmt"
	"strings"
	"time"
)

// DefaultNormalizer implements FindingsNormalizer
type DefaultNormalizer struct{}

// NewDefaultNormalizer creates a new default normalizer
func NewDefaultNormalizer() *DefaultNormalizer {
	return &DefaultNormalizer{}
}

// Normalize converts raw tool findings into normalized format
func (n *DefaultNormalizer) Normalize(rawFindings []interface{}) ([]NormalizedFinding, error) {
	var normalized []NormalizedFinding

	for _, raw := range rawFindings {
		finding, err := n.normalizeSingle(raw)
		if err != nil {
			// Skip invalid findings but continue processing
			continue
		}
		normalized = append(normalized, finding)
	}

	return normalized, nil
}

// normalizeSingle normalizes a single raw finding
func (n *DefaultNormalizer) normalizeSingle(raw interface{}) (NormalizedFinding, error) {
	rawMap, ok := raw.(map[string]interface{})
	if !ok {
		return NormalizedFinding{}, fmt.Errorf("invalid finding format")
	}

	finding := NormalizedFinding{
		Timestamp: time.Now(),
		RawData:   rawMap,
	}

	// Extract basic fields with fallbacks
	finding.Title = n.extractString(rawMap, []string{"Title", "title", "issue_text", "Message", "message"}, "No title")
	finding.Description = n.extractString(rawMap, []string{"Description", "description", "issue_text", "Message", "message"}, "")
	finding.File = n.extractString(rawMap, []string{"File", "file", "filename", "Filename", "path", "Path"}, "unknown")
	finding.Line = n.extractInt(rawMap, []string{"Line", "line", "line_number", "StartLine", "start", "Start"}, 0)
	finding.CodeSnippet = n.extractString(rawMap, []string{"code", "CodeSnippet", "code_snippet", "Match", "match"}, "")
	finding.RuleID = n.extractString(rawMap, []string{"RuleID", "rule_id", "check_id", "test_id", "ruleId", "code"}, "unknown")
	finding.Tool = n.determineTool(rawMap)

	// Normalize severity
	severityStr := n.extractString(rawMap, []string{"issue_severity", "Severity", "severity", "level", "Level"}, "unknown")
	finding.Severity = n.normalizeSeverity(severityStr)

	// Normalize confidence
	confidenceStr := n.extractString(rawMap, []string{"issue_confidence", "confidence", "Confidence"}, "unknown")
	finding.Confidence = n.normalizeConfidence(confidenceStr)

	// Determine category
	finding.Category = n.determineCategory(finding.Tool, finding.File)

	// Extract CWE
	finding.CWE = n.extractCWE(rawMap)

	// Extract CVSS
	finding.CVSS = n.extractCVSS(rawMap)

	// Extract Fix
	finding.Fix = n.extractFix(rawMap)

	// Extract tags
	finding.Tags = n.extractTags(rawMap)

	// Generate ID
	finding.ID = n.generateID(finding)

	return finding, nil
}

// normalizeSeverity converts various severity formats to standardized levels
func (n *DefaultNormalizer) normalizeSeverity(sev string) SeverityLevel {
	sev = strings.ToUpper(strings.TrimSpace(sev))

	switch sev {
	case "CRITICAL", "CRIT", "C":
		return Critical
	case "HIGH", "H", "ERROR":
		return High
	case "MEDIUM", "MED", "M", "WARNING":
		return Medium
	case "LOW", "L":
		return Low
	case "STYLE", "INFO", "INFORMATION", "I", "UNKNOWN", "":
		return Info
	default:
		return Info
	}
}

// normalizeConfidence converts various confidence formats to standardized levels
func (n *DefaultNormalizer) normalizeConfidence(conf string) ConfidenceLevel {
	conf = strings.ToUpper(strings.TrimSpace(conf))

	switch conf {
	case "HIGH", "CERTAIN", "C":
		return Certain
	case "MEDIUM", "LIKELY", "L":
		return Likely
	case "LOW", "POSSIBLE", "P", "UNKNOWN", "":
		return Possible
	default:
		return Possible
	}
}

// determineTool determines the tool that generated the finding
func (n *DefaultNormalizer) determineTool(rawMap map[string]interface{}) string {
	// Check for bandit format
	if testID, exists := rawMap["test_id"]; exists {
		if testIDStr, ok := testID.(string); ok && strings.HasPrefix(testIDStr, "B") {
			return "bandit"
		}
	}

	// Check for semgrep format
	if _, exists := rawMap["check_id"]; exists {
		return "semgrep"
	}

	// Check for gitleaks format
	if _, exists := rawMap["Secret"]; exists {
		return "gitleaks"
	}

	// Check for trivy format
	if _, exists := rawMap["VulnerabilityID"]; exists {
		return "trivy"
	}

	// Check for hadolint format
	if code, exists := rawMap["code"]; exists {
		if codeStr, ok := code.(string); ok && (strings.HasPrefix(codeStr, "DL") || strings.HasPrefix(codeStr, "SH")) {
			return "hadolint"
		}
	}

	// Check for njsscan format
	if _, exists := rawMap["njsscan_version"]; exists {
		return "njsscan"
	}
	if _, exists := rawMap["nodejs"]; exists {
		return "njsscan"
	}

	// Fallback to explicit tool field
	return n.extractString(rawMap, []string{"_tool", "tool", "Tool"}, "unknown")
}

// determineCategory determines the finding category based on tool and file
func (n *DefaultNormalizer) determineCategory(tool, file string) FindingCategory {
	// By tool
	switch tool {
	case "gitleaks_results", "wallet_gitleaks_results", "gitleaks":
		return SecretFinding
	case "bandit_results", "bandit", "semgrep_results", "semgrep", "njsscan_results", "njsscan", "gosec_results", "gosec":
		return CodeFinding
	case "trivy_results", "trivy", "osv_results", "osv":
		return VulnFinding
	case "hadolint_results", "hadolint":
		return ConfigFinding
	}

	// By file extension
	if strings.Contains(file, "Dockerfile") || strings.Contains(file, ".yaml") || strings.Contains(file, ".yml") {
		return ConfigFinding
	}
	if strings.HasSuffix(file, ".go") || strings.HasSuffix(file, ".py") || strings.HasSuffix(file, ".js") ||
		strings.HasSuffix(file, ".ts") || strings.HasSuffix(file, ".java") || strings.HasSuffix(file, ".c") ||
		strings.HasSuffix(file, ".cpp") {
		return CodeFinding
	}

	return UnknownFinding
}

// extractCWE extracts CWE identifiers from the finding
func (n *DefaultNormalizer) extractCWE(rawMap map[string]interface{}) []string {
	var cwe []string

	// Check various CWE fields
	cweFields := []string{"cwe", "CWE", "issue_cwe"}
	for _, field := range cweFields {
		if val, exists := rawMap[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				cwe = append(cwe, strVal)
			} else if arrVal, ok := val.([]interface{}); ok {
				for _, item := range arrVal {
					if strItem, ok := item.(string); ok && strItem != "" {
						cwe = append(cwe, strItem)
					}
				}
			}
		}
	}

	return cwe
}

// extractCVSS extracts CVSS score information
func (n *DefaultNormalizer) extractCVSS(rawMap map[string]interface{}) *CVSSScore {
	// Look for CVSS in various tool formats
	cvssFields := []string{"cvss", "CVSS", "Cvss", "cvss_score"}
	for _, field := range cvssFields {
		if val, exists := rawMap[field]; exists {
			// Handle map structure (like Trivy)
			if cvssMap, ok := val.(map[string]interface{}); ok {
				score := 0.0
				version := "3.1"
				vector := ""

				// Try to find a score (Trivy often has sub-maps like "ghsa", "redhat")
				for _, subVal := range cvssMap {
					if subMap, ok := subVal.(map[string]interface{}); ok {
						if v3Score, ok := subMap["V3Score"].(float64); ok {
							score = v3Score
							break
						}
						if v2Score, ok := subMap["V2Score"].(float64); ok {
							score = v2Score
							version = "2.0"
							break
						}
					}
				}

				if score > 0 {
					return &CVSSScore{
						Version:   version,
						BaseScore: score,
						Vector:    vector,
						Severity:  n.scoreToSeverityString(score),
					}
				}
			}

			// Handle direct float/string score
			if score, ok := val.(float64); ok {
				return &CVSSScore{
					Version:   "3.1",
					BaseScore: score,
					Severity:  n.scoreToSeverityString(score),
				}
			}
		}
	}
	return nil
}

// scoreToSeverityString converts CVSS score to severity string
func (n *DefaultNormalizer) scoreToSeverityString(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 0.1 {
		return "LOW"
	}
	return "INFO"
}

// extractFix extracts fix suggestions
func (n *DefaultNormalizer) extractFix(rawMap map[string]interface{}) *FixSuggestion {
	// Check common fix fields
	fixFields := []string{"fix", "Fix", "suggestion", "Suggestion", "remediation", "Remediation"}
	for _, field := range fixFields {
		if val, exists := rawMap[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return &FixSuggestion{
					Description: strVal,
				}
			}
			if fixMap, ok := val.(map[string]interface{}); ok {
				return &FixSuggestion{
					Description: n.extractString(fixMap, []string{"Description", "message", "text"}, ""),
					Code:        n.extractString(fixMap, []string{"Code", "replacement", "diff"}, ""),
				}
			}
		}
	}

	// Check for fixed_version (common in vulnerability tools)
	if fixedVersion, ok := rawMap["FixedVersion"].(string); ok && fixedVersion != "" {
		return &FixSuggestion{
			Description: fmt.Sprintf("Upgrade to version %s", fixedVersion),
		}
	}

	return nil
}

// extractTags extracts tags from the finding
func (n *DefaultNormalizer) extractTags(rawMap map[string]interface{}) []string {
	var tags []string

	if tagsVal, exists := rawMap["Tags"]; exists {
		if tagsArr, ok := tagsVal.([]interface{}); ok {
			for _, tag := range tagsArr {
				if strTag, ok := tag.(string); ok {
					tags = append(tags, strTag)
				}
			}
		}
	}

	return tags
}

// generateID generates a unique ID for the finding
func (n *DefaultNormalizer) generateID(finding NormalizedFinding) string {
	idStr := fmt.Sprintf("%s_%s_%d_%s", finding.Tool, finding.File, finding.Line, finding.RuleID)
	hash := md5.Sum([]byte(idStr))
	return fmt.Sprintf("%x", hash)[:16]
}

// extractString extracts a string value from multiple possible field names
func (n *DefaultNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
		}
	}
	return defaultValue
}

// extractInt extracts an int value from multiple possible field names
func (n *DefaultNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(int); ok {
				return intVal
			} else if floatVal, ok := val.(float64); ok {
				return int(floatVal)
			}
		}
	}
	return defaultValue
}
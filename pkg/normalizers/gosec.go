package normalizers

import (
	"encoding/json"
	"fmt"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// GosecNormalizer handles Gosec Go security scanner output
type GosecNormalizer struct{}

// NewGosecNormalizer creates a new Gosec normalizer
func NewGosecNormalizer() *GosecNormalizer {
	return &GosecNormalizer{}
}

// ToolName returns the tool name
func (n *GosecNormalizer) ToolName() string {
	return "gosec"
}

// CanHandle checks if this normalizer can handle the given data
func (n *GosecNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	// Gosec has "Issues" array and "GosecVersion" field
	_, hasIssues := data["Issues"]
	_, hasVersion := data["GosecVersion"]

	if !hasIssues || !hasVersion {
		return false
	}

	// Check if Issues is an array
	issues, ok := data["Issues"].([]interface{})
	if !ok {
		return false
	}

	// If there are issues, check the first one has Gosec-specific fields
	if len(issues) > 0 {
		firstIssue, ok := issues[0].(map[string]interface{})
		if !ok {
			return false
		}

		// Gosec has rule_id field starting with "G"
		if ruleID, exists := firstIssue["rule_id"]; exists {
			if ruleIDStr, ok := ruleID.(string); ok && len(ruleIDStr) > 0 && ruleIDStr[0] == 'G' {
				return true
			}
		}
	}

	// Empty issues array is also valid Gosec output
	return true
}

// Normalize converts Gosec output to normalized findings
func (n *GosecNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse gosec JSON: %w", err)
	}

	issues, ok := data["Issues"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("gosec Issues not found or not an array")
	}

	var normalized []findings_processor.NormalizedFinding

	for _, issue := range issues {
		issueMap, ok := issue.(map[string]interface{})
		if !ok {
			continue
		}

		finding, err := n.normalizeSingleIssue(issueMap)
		if err != nil {
			// Skip invalid results but continue processing
			continue
		}

		normalized = append(normalized, finding)
	}

	return normalized, nil
}

// normalizeSingleIssue converts a single Gosec issue to normalized finding
func (n *GosecNormalizer) normalizeSingleIssue(issue map[string]interface{}) (findings_processor.NormalizedFinding, error) {
	finding := findings_processor.NormalizedFinding{
		RawData: issue,
	}

	// Extract basic fields
	finding.Title = n.extractString(issue, []string{"details", "title"}, "Security issue detected")
	finding.Description = n.extractString(issue, []string{"details", "description"}, "")
	finding.File = n.extractString(issue, []string{"file"}, "unknown")
	finding.Line = n.extractInt(issue, []string{"line"}, 0)
	finding.RuleID = n.extractString(issue, []string{"rule_id"}, "unknown")
	finding.Tool = "gosec"

	// Extract code snippet
	if code, exists := issue["code"]; exists {
		if codeStr, ok := code.(string); ok {
			finding.CodeSnippet = codeStr
		}
	}

	// Normalize severity
	severityStr := n.extractString(issue, []string{"severity"}, "LOW")
	finding.Severity = n.normalizeSeverity(severityStr)

	// Normalize confidence
	confidenceStr := n.extractString(issue, []string{"confidence"}, "LOW")
	finding.Confidence = n.normalizeConfidence(confidenceStr)

	// Category is always code for Gosec
	finding.Category = findings_processor.CodeFinding

	// Extract CWE
	finding.CWE = n.extractCWE(issue)

	// Generate ID
	finding.ID = n.generateID(finding)

	return finding, nil
}

// normalizeSeverity converts Gosec severity to standard levels
func (n *GosecNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch sev {
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

// normalizeConfidence converts Gosec confidence to standard levels
func (n *GosecNormalizer) normalizeConfidence(conf string) findings_processor.ConfidenceLevel {
	switch conf {
	case "HIGH":
		return findings_processor.Certain
	case "MEDIUM":
		return findings_processor.Likely
	case "LOW":
		return findings_processor.Possible
	default:
		return findings_processor.Possible
	}
}

// extractCWE extracts CWE from Gosec issue
func (n *GosecNormalizer) extractCWE(issue map[string]interface{}) []string {
	var cwe []string

	if cweData, exists := issue["cwe"]; exists {
		if cweMap, ok := cweData.(map[string]interface{}); ok {
			if id, exists := cweMap["id"]; exists {
				if idFloat, ok := id.(float64); ok {
					cwe = append(cwe, fmt.Sprintf("CWE-%d", int(idFloat)))
				} else if idStr, ok := id.(string); ok {
					cwe = append(cwe, idStr)
				}
			}
		}
	}

	return cwe
}

// generateID generates a unique ID for the finding
func (n *GosecNormalizer) generateID(finding findings_processor.NormalizedFinding) string {
	return fmt.Sprintf("gosec_%s_%s_%d", finding.File, finding.RuleID, finding.Line)
}

// Helper methods
func (n *GosecNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}

func (n *GosecNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(float64); ok {
				return int(intVal)
			}
		}
	}
	return defaultValue
}

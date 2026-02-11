package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// BanditNormalizer handles Bandit security scanner output
type BanditNormalizer struct{}

// NewBanditNormalizer creates a new Bandit normalizer
func NewBanditNormalizer() *BanditNormalizer {
	return &BanditNormalizer{}
}

// ToolName returns the tool name
func (n *BanditNormalizer) ToolName() string {
	return "bandit"
}

// CanHandle checks if this normalizer can handle the given data
func (n *BanditNormalizer) CanHandle(rawData []byte) bool {
	// Check if it's Bandit format (has results array with test_id starting with B)
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	// Check for results array
	results, hasResults := data["results"]
	if !hasResults {
		return false
	}

	resultsArray, ok := results.([]interface{})
	if !ok || len(resultsArray) == 0 {
		return false
	}

	// Check if first result has bandit-specific fields
	firstResult, ok := resultsArray[0].(map[string]interface{})
	if !ok {
		return false
	}

	// Bandit has test_id field starting with "B"
	if testID, exists := firstResult["test_id"]; exists {
		if testIDStr, ok := testID.(string); ok && strings.HasPrefix(testIDStr, "B") {
			return true
		}
	}

	return false
}

// Normalize converts Bandit output to normalized findings
func (n *BanditNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse bandit JSON: %w", err)
	}

	results, ok := data["results"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("bandit results not found or not an array")
	}

	var normalized []findings_processor.NormalizedFinding

	for _, result := range results {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		finding, err := n.normalizeSingleResult(resultMap)
		if err != nil {
			// Skip invalid results but continue processing
			continue
		}

		normalized = append(normalized, finding)
	}

	return normalized, nil
}

// normalizeSingleResult converts a single Bandit result to normalized finding
func (n *BanditNormalizer) normalizeSingleResult(result map[string]interface{}) (findings_processor.NormalizedFinding, error) {
	finding := findings_processor.NormalizedFinding{
		RawData: result,
	}

	// Extract basic fields
	finding.Title = n.extractString(result, []string{"issue_text", "title"}, "No title")
	finding.Description = n.extractString(result, []string{"issue_text", "description"}, "")
	finding.File = n.extractString(result, []string{"filename", "file"}, "unknown")
	finding.Line = n.extractInt(result, []string{"line_number", "line"}, 0)
	finding.CodeSnippet = n.extractString(result, []string{"code", "snippet"}, "")
	finding.RuleID = n.extractString(result, []string{"test_id", "rule_id"}, "unknown")
	finding.Tool = "bandit"

	// Normalize severity (Bandit uses LOW/MEDIUM/HIGH)
	severityStr := n.extractString(result, []string{"issue_severity"}, "unknown")
	finding.Severity = n.normalizeSeverity(severityStr)

	// Normalize confidence (Bandit uses LOW/MEDIUM/HIGH)
	confidenceStr := n.extractString(result, []string{"issue_confidence"}, "unknown")
	finding.Confidence = n.normalizeConfidence(confidenceStr)

	// Determine category
	finding.Category = n.determineCategory(finding.RuleID)

	// Extract CWE
	finding.CWE = n.extractCWE(result)

	// Generate ID
	finding.ID = n.generateID(finding)

	return finding, nil
}

// normalizeSeverity converts Bandit severity to standard levels
func (n *BanditNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return findings_processor.High
	case "MEDIUM":
		return findings_processor.Medium
	case "LOW":
		return findings_processor.Low
	default:
		return findings_processor.Info
	}
}

// normalizeConfidence converts Bandit confidence to standard levels
func (n *BanditNormalizer) normalizeConfidence(conf string) findings_processor.ConfidenceLevel {
	switch strings.ToUpper(conf) {
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

// determineCategory determines finding category based on Bandit rule ID
func (n *BanditNormalizer) determineCategory(ruleID string) findings_processor.FindingCategory {
	// Bandit rule IDs indicate the type of issue
	if strings.Contains(ruleID, "B1") { // B101 - assert_used
		return findings_processor.CodeFinding
	}
	if strings.Contains(ruleID, "B3") { // B301 - pickle, B311 - random, etc.
		return findings_processor.CodeFinding
	}
	if strings.Contains(ruleID, "B5") { // B501-B508 - crypto issues
		return findings_processor.CodeFinding
	}
	if strings.Contains(ruleID, "B6") { // B601-B608 - subprocess issues
		return findings_processor.CodeFinding
	}

	// Default to code finding for Bandit
	return findings_processor.CodeFinding
}

// extractCWE extracts CWE from Bandit result
func (n *BanditNormalizer) extractCWE(result map[string]interface{}) []string {
	var cwe []string

	if issueCwe, exists := result["issue_cwe"]; exists {
		if cweMap, ok := issueCwe.(map[string]interface{}); ok {
			if id, exists := cweMap["id"]; exists {
				if idStr, ok := id.(float64); ok {
					cwe = append(cwe, fmt.Sprintf("CWE-%d", int(idStr)))
				}
			}
		}
	}

	return cwe
}

// generateID generates a unique ID for the finding
func (n *BanditNormalizer) generateID(finding findings_processor.NormalizedFinding) string {
	return fmt.Sprintf("bandit_%s_%s_%d", finding.File, finding.RuleID, finding.Line)
}

// Helper methods for extracting values
func (n *BanditNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}

func (n *BanditNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(float64); ok {
				return int(intVal)
			}
		}
	}
	return defaultValue
}
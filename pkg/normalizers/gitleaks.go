package normalizers

import (
	"encoding/json"
	"fmt"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// GitleaksNormalizer handles Gitleaks secret scanner output
type GitleaksNormalizer struct{}

// NewGitleaksNormalizer creates a new Gitleaks normalizer
func NewGitleaksNormalizer() *GitleaksNormalizer {
	return &GitleaksNormalizer{}
}

// ToolName returns the tool name
func (n *GitleaksNormalizer) ToolName() string {
	return "gitleaks"
}

// CanHandle checks if this normalizer can handle the given data
func (n *GitleaksNormalizer) CanHandle(rawData []byte) bool {
	// Try to parse as array first (Gitleaks format)
	var data []interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	if len(data) == 0 {
		return false
	}

	// Check if first element has Gitleaks-specific fields
	firstResult, ok := data[0].(map[string]interface{})
	if !ok {
		return false
	}

	// Gitleaks has "Secret" field and "RuleID" field
	_, hasSecret := firstResult["Secret"]
	_, hasRuleID := firstResult["RuleID"]

	return hasSecret && hasRuleID
}

// Normalize converts Gitleaks output to normalized findings
func (n *GitleaksNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data []interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks JSON: %w", err)
	}

	var normalized []findings_processor.NormalizedFinding

	for _, result := range data {
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

// normalizeSingleResult converts a single Gitleaks result to normalized finding
func (n *GitleaksNormalizer) normalizeSingleResult(result map[string]interface{}) (findings_processor.NormalizedFinding, error) {
	finding := findings_processor.NormalizedFinding{
		RawData: result,
	}

	// Extract basic fields
	finding.Title = n.extractString(result, []string{"Description", "title"}, "Secret detected")
	finding.Description = n.extractString(result, []string{"Description", "description"}, "")
	finding.File = n.extractString(result, []string{"File", "file"}, "unknown")
	finding.Line = n.extractInt(result, []string{"StartLine", "line"}, 0)
	finding.RuleID = n.extractString(result, []string{"RuleID", "rule_id"}, "unknown")
	finding.Tool = "gitleaks"

	// All secrets are high severity, high confidence
	finding.Severity = findings_processor.High
	finding.Confidence = findings_processor.Certain

	// Category is always secret
	finding.Category = findings_processor.SecretFinding

	// Extract match as code snippet
	if match, exists := result["Match"]; exists {
		if matchStr, ok := match.(string); ok {
			finding.CodeSnippet = matchStr
		}
	}

	// Generate ID
	finding.ID = n.generateID(finding)

	return finding, nil
}

// generateID generates a unique ID for the finding
func (n *GitleaksNormalizer) generateID(finding findings_processor.NormalizedFinding) string {
	return fmt.Sprintf("gitleaks_%s_%s_%d", finding.File, finding.RuleID, finding.Line)
}

// Helper methods
func (n *GitleaksNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}

func (n *GitleaksNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(float64); ok {
				return int(intVal)
			}
		}
	}
	return defaultValue
}
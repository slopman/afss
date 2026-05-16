package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
	"github.com/security-scanner/afss-orchestrator/pkg/util"
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
	data, err := parseGitleaksJSONArray(rawData)
	if err != nil || len(data) == 0 {
		return false
	}
	firstResult, ok := data[0].(map[string]interface{})
	if !ok {
		return false
	}
	_, hasSecret := firstResult["Secret"]
	_, hasRuleID := firstResult["RuleID"]
	return hasSecret && hasRuleID
}

// Normalize converts Gitleaks output to normalized findings
func (n *GitleaksNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	data, err := parseGitleaksJSONArray(rawData)
	if err != nil {
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

// parseGitleaksJSONArray accepts a JSON array, a single finding object, NDJSON lines,
// or stdout with trailing non-JSON noise after the first complete JSON value.
func parseGitleaksJSONArray(rawData []byte) ([]interface{}, error) {
	s := strings.TrimSpace(string(rawData))
	if s == "" {
		return nil, fmt.Errorf("empty gitleaks output")
	}
	if frag := util.FirstJSONValue(s); frag != "" {
		s = frag
	}
	var asArray []interface{}
	if err := json.Unmarshal([]byte(s), &asArray); err == nil {
		return asArray, nil
	}
	var asObj map[string]interface{}
	if err := json.Unmarshal([]byte(s), &asObj); err == nil {
		if _, ok := asObj["RuleID"]; ok {
			return []interface{}{asObj}, nil
		}
	}
	var lines []interface{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if _, ok := m["RuleID"]; ok {
			lines = append(lines, m)
		}
	}
	if len(lines) > 0 {
		return lines, nil
	}
	return nil, fmt.Errorf("unrecognized gitleaks output shape")
}
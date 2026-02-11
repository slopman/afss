package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// HadolintNormalizer handles Hadolint output
type HadolintNormalizer struct{}

// NewHadolintNormalizer creates a new Hadolint normalizer
func NewHadolintNormalizer() *HadolintNormalizer {
	return &HadolintNormalizer{}
}

// ToolName returns the tool name
func (n *HadolintNormalizer) ToolName() string {
	return "hadolint"
}

// CanHandle checks if this normalizer can handle the given data
func (n *HadolintNormalizer) CanHandle(rawData []byte) bool {
	// Hadolint output is typically a JSON array of objects
	var results []map[string]interface{}
	if err := json.Unmarshal(rawData, &results); err != nil {
		return false
	}

	if len(results) == 0 {
		return false
	}

	// Check if first result has hadolint-specific fields
	// Hadolint results have "code" (starts with DL or SH), "level", "message"
	first := results[0]
	code, hasCode := first["code"].(string)
	_, hasLevel := first["level"].(string)
	_, hasMessage := first["message"].(string)

	if hasCode && hasLevel && hasMessage {
		if strings.HasPrefix(code, "DL") || strings.HasPrefix(code, "SH") {
			return true
		}
	}

	return false
}

// Normalize converts Hadolint output to normalized findings
func (n *HadolintNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var results []map[string]interface{}
	if err := json.Unmarshal(rawData, &results); err != nil {
		return nil, fmt.Errorf("failed to parse hadolint JSON: %w", err)
	}

	var normalized []findings_processor.NormalizedFinding

	for _, result := range results {
		finding := findings_processor.NormalizedFinding{
			RawData: result,
			Tool:    "hadolint",
		}

		// Extract fields using helpers
		finding.Title = n.extractString(result, []string{"message"}, "No message")
		finding.Description = finding.Title
		finding.File = n.extractString(result, []string{"file"}, "Dockerfile")
		finding.Line = n.extractInt(result, []string{"line"}, 0)
		finding.RuleID = n.extractString(result, []string{"code"}, "unknown")
		
		// Hadolint categories are configuration-related
		finding.Category = findings_processor.ConfigFinding
		
		// Default confidence for linter rules
		finding.Confidence = findings_processor.Certain

		// Map severity
		severityStr := n.extractString(result, []string{"level"}, "info")
		finding.Severity = n.normalizeSeverity(severityStr)

		// Generate ID
		finding.ID = fmt.Sprintf("hadolint_%s_%s_%d", finding.File, finding.RuleID, finding.Line)

		normalized = append(normalized, finding)
	}

	return normalized, nil
}

// normalizeSeverity converts Hadolint level to standard levels
func (n *HadolintNormalizer) normalizeSeverity(level string) findings_processor.SeverityLevel {
	switch strings.ToLower(level) {
	case "error":
		return findings_processor.High
	case "warning":
		return findings_processor.Medium
	case "info":
		return findings_processor.Low
	case "style":
		return findings_processor.Info
	default:
		return findings_processor.Info
	}
}

// Helper methods for extracting values
func (n *HadolintNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}

func (n *HadolintNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(float64); ok {
				return int(intVal)
			}
			if intVal, ok := val.(int); ok {
				return intVal
			}
		}
	}
	return defaultValue
}

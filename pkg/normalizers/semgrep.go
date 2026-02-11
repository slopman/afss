package normalizers

import (
	"encoding/json"
	"fmt"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// SemgrepNormalizer handles Semgrep code analysis output
type SemgrepNormalizer struct{}

// NewSemgrepNormalizer creates a new Semgrep normalizer
func NewSemgrepNormalizer() *SemgrepNormalizer {
	return &SemgrepNormalizer{}
}

// ToolName returns the tool name
func (n *SemgrepNormalizer) ToolName() string {
	return "semgrep"
}

// CanHandle checks if this normalizer can handle the given data
func (n *SemgrepNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	// Semgrep has "version", "results" array, and specific structure
	version, hasVersion := data["version"]
	results, hasResults := data["results"]

	if !hasVersion || !hasResults {
		return false
	}

	// Version should be string
	if _, ok := version.(string); !ok {
		return false
	}

	// Results should be array
	resultsArray, ok := results.([]interface{})
	if !ok || len(resultsArray) == 0 {
		return false
	}

	// Check first result has semgrep-specific fields
	firstResult, ok := resultsArray[0].(map[string]interface{})
	if !ok {
		return false
	}

	// Semgrep has check_id, path, start, end, extra
	_, hasCheckID := firstResult["check_id"]
	_, hasPath := firstResult["path"]
	_, hasExtra := firstResult["extra"]

	return hasCheckID && hasPath && hasExtra
}

// Normalize converts Semgrep output to normalized findings
func (n *SemgrepNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep JSON: %w", err)
	}

	results, ok := data["results"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("semgrep results not found or not an array")
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

// normalizeSingleResult converts a single Semgrep result to normalized finding
func (n *SemgrepNormalizer) normalizeSingleResult(result map[string]interface{}) (findings_processor.NormalizedFinding, error) {
	finding := findings_processor.NormalizedFinding{
		RawData: result,
	}

	// Extract basic fields
	finding.RuleID = n.extractString(result, []string{"check_id"}, "unknown")
	finding.File = n.extractString(result, []string{"path"}, "unknown")
	finding.Tool = "semgrep"

	// Extract line number from start position
	if start, exists := result["start"]; exists {
		if startMap, ok := start.(map[string]interface{}); ok {
			finding.Line = n.extractInt(startMap, []string{"line"}, 0)
		}
	}

	// Extract info from extra field
	if extra, exists := result["extra"]; exists {
		if extraMap, ok := extra.(map[string]interface{}); ok {
			finding.Title = n.extractString(extraMap, []string{"message"}, "Semgrep finding")
			finding.CodeSnippet = n.extractString(extraMap, []string{"lines"}, "")

			// Normalize severity
			severityStr := n.extractString(extraMap, []string{"severity"}, "INFO")
			finding.Severity = n.normalizeSeverity(severityStr)

			// Extract metadata
			if metadata, exists := extraMap["metadata"]; exists {
				if metaMap, ok := metadata.(map[string]interface{}); ok {
					finding.CWE = n.extractCWE(metaMap)
				}
			}
		}
	}

	// All semgrep findings are code issues
	finding.Category = findings_processor.CodeFinding

	// Semgrep confidence is usually high
	finding.Confidence = findings_processor.Likely

	// Generate ID
	finding.ID = n.generateID(finding)

	return finding, nil
}

// normalizeSeverity converts Semgrep severity to standard levels
func (n *SemgrepNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch sev {
	case "ERROR", "CRITICAL":
		return findings_processor.Critical
	case "WARNING", "HIGH":
		return findings_processor.High
	case "INFO", "MEDIUM":
		return findings_processor.Medium
	case "LOW":
		return findings_processor.Low
	default:
		return findings_processor.Info
	}
}

// extractCWE extracts CWE from Semgrep metadata
func (n *SemgrepNormalizer) extractCWE(metadata map[string]interface{}) []string {
	var cwe []string

	if cweIDs, exists := metadata["cwe"]; exists {
		if cweStr, ok := cweIDs.(string); ok {
			cwe = append(cwe, cweStr)
		} else if cweArray, ok := cweIDs.([]interface{}); ok {
			for _, cweID := range cweArray {
				if cweStr, ok := cweID.(string); ok {
					cwe = append(cwe, cweStr)
				}
			}
		}
	}

	return cwe
}

// generateID generates a unique ID for the finding
func (n *SemgrepNormalizer) generateID(finding findings_processor.NormalizedFinding) string {
	return fmt.Sprintf("semgrep_%s_%s_%d", finding.File, finding.RuleID, finding.Line)
}

// Helper methods
func (n *SemgrepNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}

func (n *SemgrepNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(float64); ok {
				return int(intVal)
			}
		}
	}
	return defaultValue
}
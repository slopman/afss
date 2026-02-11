package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// NjsscanNormalizer handles Njsscan output
type NjsscanNormalizer struct{}

// NewNjsscanNormalizer creates a new Njsscan normalizer
func NewNjsscanNormalizer() *NjsscanNormalizer {
	return &NjsscanNormalizer{}
}

// ToolName returns the tool name
func (n *NjsscanNormalizer) ToolName() string {
	return "njsscan"
}

// CanHandle checks if this normalizer can handle the given data
func (n *NjsscanNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}

	if _, exists := data["njsscan_version"]; exists {
		return true
	}

	if _, exists := data["nodejs"]; exists {
		return true
	}

	return false
}

// Normalize converts Njsscan output to normalized findings
func (n *NjsscanNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse njsscan JSON: %w", err)
	}

	var normalized []findings_processor.NormalizedFinding

	nodejs, ok := data["nodejs"].(map[string]interface{})
	if !ok {
		return []findings_processor.NormalizedFinding{}, nil
	}

	for ruleID, ruleData := range nodejs {
		rMap, ok := ruleData.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, _ := rMap["metadata"].(map[string]interface{})
		files, _ := rMap["files"].([]interface{})

		severityStr := n.extractString(metadata, "severity", "INFO")
		severity := n.normalizeSeverity(severityStr)
		description := n.extractString(metadata, "description", "No description")
		cweStr := n.extractString(metadata, "cwe", "")
		cwe := n.parseCWE(cweStr)

		if len(files) == 0 {
			// Global finding
			finding := findings_processor.NormalizedFinding{
				ID:          fmt.Sprintf("njsscan_%s_global", ruleID),
				Title:       description,
				Description: description,
				Severity:    severity,
				Confidence:  findings_processor.Certain,
				Category:    findings_processor.CodeFinding,
				Tool:        "njsscan",
				RuleID:      ruleID,
				File:        "global",
				CWE:         cwe,
				RawData:     rMap,
			}
			normalized = append(normalized, finding)
			continue
		}

		for _, f := range files {
			fMap, ok := f.(map[string]interface{})
			if !ok {
				continue
			}

			filePath := n.extractString(fMap, "file_path", "unknown")
			line := n.extractFirstInt(fMap, "match_lines", 0)

			finding := findings_processor.NormalizedFinding{
				ID:          fmt.Sprintf("njsscan_%s_%s_%d", ruleID, filePath, line),
				Title:       description,
				Description: description,
				Severity:    severity,
				Confidence:  findings_processor.Certain,
				Category:    findings_processor.CodeFinding,
				Tool:        "njsscan",
				RuleID:      ruleID,
				File:        filePath,
				Line:        line,
				CWE:         cwe,
				RawData:     fMap,
			}
			// Add metadata to RawData
			for k, v := range metadata {
				finding.RawData["metadata_"+k] = v
			}

			normalized = append(normalized, finding)
		}
	}

	return normalized, nil
}

// normalizeSeverity converts Njsscan severity to standard levels
func (n *NjsscanNormalizer) normalizeSeverity(sev string) findings_processor.SeverityLevel {
	switch strings.ToUpper(sev) {
	case "ERROR":
		return findings_processor.High
	case "WARNING":
		return findings_processor.Medium
	case "INFO":
		return findings_processor.Low
	default:
		return findings_processor.Info
	}
}

// parseCWE extracts CWE ID from njsscan CWE string (e.g., "CWE-352: ...")
func (n *NjsscanNormalizer) parseCWE(cweStr string) []string {
	if cweStr == "" {
		return []string{}
	}
	parts := strings.Split(cweStr, ":")
	if len(parts) > 0 {
		return []string{strings.TrimSpace(parts[0])}
	}
	return []string{}
}

// Helper methods for extracting values
func (n *NjsscanNormalizer) extractString(data map[string]interface{}, field string, defaultValue string) string {
	if val, exists := data[field]; exists {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}

func (n *NjsscanNormalizer) extractFirstInt(data map[string]interface{}, field string, defaultValue int) int {
	if val, exists := data[field]; exists {
		if arr, ok := val.([]interface{}); ok && len(arr) > 0 {
			if intVal, ok := arr[0].(float64); ok {
				return int(intVal)
			}
		}
	}
	return defaultValue
}

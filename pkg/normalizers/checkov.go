package normalizers

import (
	"encoding/json"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// CheckovNormalizer handles Checkov security scanner output
type CheckovNormalizer struct{}

// NewCheckovNormalizer creates a new Checkov normalizer
func NewCheckovNormalizer() *CheckovNormalizer {
	return &CheckovNormalizer{}
}

// ToolName returns the tool name
func (n *CheckovNormalizer) ToolName() string {
	return "checkov"
}

// CanHandle checks if this normalizer can handle the given data
func (n *CheckovNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}
	
	if _, exists := data["check_type"]; exists {
		return true
	}
	if _, exists := data["results"]; exists {
		results, ok := data["results"].(map[string]interface{})
		if ok {
			if _, exists := results["failed_checks"]; exists {
				return true
			}
		}
	}
	return false
}

// Normalize converts Checkov output to normalized findings
func (n *CheckovNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, err
	}

	var rawResults []interface{}
	
	// Handle full checkov report
	if results, ok := data["results"].(map[string]interface{}); ok {
		if failed, ok := results["failed_checks"].([]interface{}); ok {
			rawResults = append(rawResults, failed...)
		}
	} else if failed, ok := data["failed_checks"].([]interface{}); ok {
		// Handle partial report
		rawResults = append(rawResults, failed...)
	} else {
		// Try treating the whole thing as one finding
		rawResults = append(rawResults, data)
	}

	dn := findings_processor.NewDefaultNormalizer()
	findings, err := dn.Normalize(rawResults)
	if err != nil {
		return nil, err
	}

	for i := range findings {
		findings[i].Tool = "checkov"
		findings[i].Category = findings_processor.ConfigFinding
	}

	return findings, nil
}

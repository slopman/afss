package normalizers

import (
	"encoding/json"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// TruffleHogNormalizer handles TruffleHog security scanner output
type TruffleHogNormalizer struct{}

// NewTruffleHogNormalizer creates a new TruffleHog normalizer
func NewTruffleHogNormalizer() *TruffleHogNormalizer {
	return &TruffleHogNormalizer{}
}

// ToolName returns the tool name
func (n *TruffleHogNormalizer) ToolName() string {
	return "trufflehog"
}

// CanHandle checks if this normalizer can handle the given data
func (n *TruffleHogNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}
	
	// TruffleHog JSON has specific fields
	if _, exists := data["reason"]; exists {
		return true
	}
	if _, exists := data["path"]; exists {
		// Potential common field, but let's be more specific
		if _, exists := data["stringsFound"]; exists {
			return true
		}
	}
	return false
}

// Normalize converts TruffleHog output to normalized findings
func (n *TruffleHogNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	dn := findings_processor.NewDefaultNormalizer()
	
	// TruffleHog can output a single object or an array
	var data interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, err
	}

	var rawResults []interface{}
	if arr, ok := data.([]interface{}); ok {
		rawResults = arr
	} else {
		rawResults = append(rawResults, data)
	}

	findings, err := dn.Normalize(rawResults)
	if err != nil {
		return nil, err
	}

	for i := range findings {
		findings[i].Tool = "trufflehog"
		findings[i].Category = findings_processor.SecretFinding
	}

	return findings, nil
}

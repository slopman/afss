package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// GovulncheckNormalizer handles Govulncheck security scanner output
type GovulncheckNormalizer struct{}

// NewGovulncheckNormalizer creates a new Govulncheck normalizer
func NewGovulncheckNormalizer() *GovulncheckNormalizer {
	return &GovulncheckNormalizer{}
}

// ToolName returns the tool name
func (n *GovulncheckNormalizer) ToolName() string {
	return "govulncheck"
}

// CanHandle checks if this normalizer can handle the given data
func (n *GovulncheckNormalizer) CanHandle(rawData []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return false
	}
	
	// Govulncheck JSON has OSV field or specific structure
	if _, exists := data["OSV"]; exists {
		return true
	}
	return false
}

// Normalize converts Govulncheck output to normalized findings
func (n *GovulncheckNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	// Govulncheck uses ndjson or a single JSON object depending on version
	// Let's use the DefaultNormalizer's logic but with specific overrides if needed
	dn := findings_processor.NewDefaultNormalizer()
	
	// Try parsing as a single object first
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err == nil {
		findings, _ := dn.Normalize([]interface{}{data})
		return n.fixToolName(findings), nil
	}

	return nil, fmt.Errorf("untreated govulncheck format")
}

func (n *GovulncheckNormalizer) fixToolName(findings []findings_processor.NormalizedFinding) []findings_processor.NormalizedFinding {
	for i := range findings {
		findings[i].Tool = "govulncheck"
		findings[i].Category = findings_processor.VulnFinding
	}
	return findings
}

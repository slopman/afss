package normalizers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	dec := json.NewDecoder(bytes.NewReader(rawData))
	for dec.More() {
		var obj map[string]interface{}
		if err := dec.Decode(&obj); err != nil {
			return false
		}
		if _, ok := obj["osv"]; ok {
			return true
		}
		if cfg, ok := obj["config"].(map[string]interface{}); ok {
			if name, ok := cfg["scanner_name"].(string); ok && strings.Contains(strings.ToLower(name), "govulncheck") {
				return true
			}
		}
	}
	return false
}

// Normalize converts Govulncheck NDJSON output to normalized findings
func (n *GovulncheckNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	dec := json.NewDecoder(bytes.NewReader(rawData))
	var findings []findings_processor.NormalizedFinding
	for dec.More() {
		var obj map[string]interface{}
		if err := dec.Decode(&obj); err != nil {
			return nil, fmt.Errorf("govulncheck decode: %w", err)
		}
		osv, ok := obj["osv"].(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := osv["id"].(string)
		if id == "" {
			continue
		}
		summary, _ := osv["summary"].(string)
		details, _ := osv["details"].(string)
		desc := summary
		if desc == "" {
			desc = details
		}
		sevStr := govulncheckSeverity(osv)
		f := findings_processor.NormalizedFinding{
			ID:          "govulncheck-" + id,
			Title:       id,
			Description: desc,
			Severity:    mapGovulncheckSeverity(sevStr),
			Confidence:  findings_processor.Likely,
			Category:    findings_processor.VulnFinding,
			Tool:        "govulncheck",
			RuleID:      id,
			Tags:        []string{"govulncheck", id},
			RawData:     obj,
			Timestamp:   time.Now(),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func mapGovulncheckSeverity(s string) findings_processor.SeverityLevel {
	switch strings.ToLower(s) {
	case "critical":
		return findings_processor.Critical
	case "high":
		return findings_processor.High
	case "low":
		return findings_processor.Low
	case "info":
		return findings_processor.Info
	default:
		return findings_processor.Medium
	}
}

func govulncheckSeverity(osv map[string]interface{}) string {
	ds, ok := osv["database_specific"].(map[string]interface{})
	if !ok {
		return "medium"
	}
	if s, ok := ds["severity"].(string); ok && s != "" {
		return strings.ToLower(s)
	}
	return "medium"
}

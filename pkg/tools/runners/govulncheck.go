package runners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildGovulncheckArgs builds command line arguments for Govulncheck
func BuildGovulncheckArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Output format - Supported: text, json, sarif, openvex
	if format, ok := config.CLI["format"].(string); ok && format != "" {
		args = append(args, "-format", format)
	}

	// Scan mode - source (Go modules), binary (compiled binaries), extract (binary analysis)
	if mode, ok := config.CLI["mode"].(string); ok && mode != "" {
		args = append(args, "-mode", mode)
	}

	// Scan level - symbol (detailed), package (per package), module (per module)
	if scan, ok := config.CLI["scan"].(string); ok && scan != "" {
		args = append(args, "-scan", scan)
	}

	// Show additional information - Comma-separated: traces, color, version, verbose
	if show, ok := config.CLI["show"].([]interface{}); ok && len(show) > 0 {
		showOptions := make([]string, len(show))
		for i, s := range show {
			if showOption, ok := s.(string); ok {
				showOptions[i] = showOption
			}
		}
		if len(showOptions) > 0 {
			args = append(args, "-show", strings.Join(showOptions, ","))
		}
	}

	// Vulnerability database URL - Default: https://vuln.go.dev
	if db, ok := config.CLI["db"].(string); ok && db != "" {
		args = append(args, "-db", db)
	}

	// Change to directory before scanning
	if C, ok := config.CLI["C"].(string); ok && C != "" {
		args = append(args, "-C", C)
	}

	// Build tags - Comma-separated list of build tags
	if tags, ok := config.CLI["tags"].(string); ok && tags != "" {
		args = append(args, "-tags", tags)
	}

	// Analyze test files - Only valid for source mode
	if test, ok := config.CLI["test"].(bool); ok && test {
		args = append(args, "-test")
	}

	// Legacy JSON output flag - Deprecated, use format instead
	if json, ok := config.CLI["json"].(bool); ok && json {
		args = append(args, "-json")
	}

	// Target patterns (default to ./... for Go modules)
	args = append(args, "./...")
	return args, nil
}

// ParseGovulncheckFindings parses govulncheck JSON stream (multiple JSON objects) into findings.
func ParseGovulncheckFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(output))))
	for dec.More() {
		var obj map[string]interface{}
		if err := dec.Decode(&obj); err != nil {
			break
		}
		osv, ok := obj["osv"].(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := osv["id"].(string)
		summary, _ := osv["summary"].(string)
		if id == "" {
			continue
		}
		sev := "medium"
		if ds, ok := osv["database_specific"].(map[string]interface{}); ok {
			if s, ok := ds["severity"].(string); ok && s != "" {
				sev = strings.ToLower(s)
			}
		}
		finding := models.Finding{
			ID:          fmt.Sprintf("govulncheck-%s", id),
			Title:       fmt.Sprintf("Govulncheck: %s", id),
			Description: summary,
			Severity:    sev,
			Category:    "vulnerability",
			RuleID:      id,
			Tool:        "govulncheck",
			Tags:        []string{"govulncheck", "go", id},
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

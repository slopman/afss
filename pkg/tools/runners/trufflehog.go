package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildTruffleHogArgs builds command line arguments for TruffleHog Go (v3)
func BuildTruffleHogArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	// TruffleHog v3: filesystem [path] --json
	args := []string{"filesystem", repoPath, "--json"}

	// Additional options for v3
	if onlyVerified, ok := config.CLI["only_verified"].(bool); ok && onlyVerified {
		args = append(args, "--only-verified")
	}

	if noVerification, ok := config.CLI["no_verification"].(bool); ok && noVerification {
		args = append(args, "--no-verification")
	}

	return args, nil
}

// parseTruffleHogFindings parses TruffleHog Go (v3) JSON output into findings
func ParseTruffleHogFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// TruffleHog v3 outputs NDJSON (newline-delimited JSON objects)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result struct {
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
			DetectorName string `json:"DetectorName"`
			DecoderName  string `json:"DecoderName"`
			Verified     bool   `json:"Verified"`
			Raw          string `json:"Raw"`
			Redacted     string `json:"Redacted"`
		}

		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip invalid JSON lines (might be logs)
			continue
		}

		filePath := result.SourceMetadata.Data.Filesystem.File
		finding := models.Finding{
			ID:          fmt.Sprintf("trufflehog-v3-%s-%s", result.DetectorName, filePath),
			Title:       fmt.Sprintf("Secret found by %s", result.DetectorName),
			Description: fmt.Sprintf("Potential secret detected: %s", result.DetectorName),
			Severity:    "high",
			File:        filePath,
			Line:        result.SourceMetadata.Data.Filesystem.Line,
			Category:    "secret",
			RuleID:      result.DetectorName,
			Tool:        "trufflehog",
			Tags:        []string{"trufflehog", "secret", result.DetectorName},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

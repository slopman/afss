package runners

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildGosecArgs builds command line arguments for Gosec
func BuildGosecArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Output settings
	if fmt, ok := config.CLI["fmt"].(string); ok && fmt != "" {
		args = append(args, "-fmt", fmt)
	}

	if out, ok := config.CLI["out"].(string); ok && out != "" {
		args = append(args, "-out", out)
	}

	if stdout, ok := config.CLI["stdout"].(bool); ok && stdout {
		args = append(args, "-stdout")
	}

	if verbose, ok := config.CLI["verbose"].(string); ok && verbose != "" {
		args = append(args, "-verbose="+verbose)
	}

	if terse, ok := config.CLI["terse"].(bool); ok && terse {
		args = append(args, "-terse")
	}

	if color, ok := config.CLI["color"].(bool); ok && color {
		args = append(args, "-color")
	}

	// Filtering
	if severity, ok := config.CLI["severity"].(string); ok && severity != "" {
		args = append(args, "-severity", severity)
	}

	if confidence, ok := config.CLI["confidence"].(string); ok && confidence != "" {
		args = append(args, "-confidence", confidence)
	}

	if include, ok := config.CLI["include"].(string); ok && include != "" {
		args = append(args, "-include="+include)
	}

	if exclude, ok := config.CLI["exclude"].(string); ok && exclude != "" {
		args = append(args, "-exclude="+exclude)
	}

	if excludeRules, ok := config.CLI["exclude_rules"].(string); ok && excludeRules != "" {
		args = append(args, "--exclude-rules="+excludeRules)
	}

	// Behavior
	if noFail, ok := config.CLI["no_fail"].(bool); ok && noFail {
		args = append(args, "-no-fail")
	}

	if quiet, ok := config.CLI["quiet"].(bool); ok && quiet {
		args = append(args, "-quiet")
	}

	if tests, ok := config.CLI["tests"].(bool); ok && tests {
		args = append(args, "-tests")
	}

	if excludeGenerated, ok := config.CLI["exclude_generated"].(bool); ok && excludeGenerated {
		args = append(args, "-exclude-generated")
	}

	if showIgnored, ok := config.CLI["show_ignored"].(bool); ok && showIgnored {
		args = append(args, "-show-ignored")
	}

	// Performance
	if concurrency, ok := config.CLI["concurrency"].(int); ok && concurrency > 0 {
		args = append(args, fmt.Sprintf("-concurrency=%d", concurrency))
	}

	// Security features
	if nosec, ok := config.CLI["nosec"].(bool); ok && nosec {
		args = append(args, "-nosec")
	}

	if nosecTag, ok := config.CLI["nosec_tag"].(string); ok && nosecTag != "" {
		args = append(args, "-nosec-tag="+nosecTag)
	}

	if trackSuppressions, ok := config.CLI["track_suppressions"].(bool); ok && trackSuppressions {
		args = append(args, "-track-suppressions")
	}

	if enableAudit, ok := config.CLI["enable_audit"].(bool); ok && enableAudit {
		args = append(args, "-enable-audit")
	}

	// Build settings
	if tags, ok := config.CLI["tags"].(string); ok && tags != "" {
		args = append(args, "-tags="+tags)
	}

	// AI features
	if aiProvider, ok := config.CLI["ai_api_provider"].(string); ok && aiProvider != "" {
		args = append(args, "-ai-api-provider="+aiProvider)
	}

	if aiKey, ok := config.CLI["ai_api_key"].(string); ok && aiKey != "" {
		args = append(args, "-ai-api-key="+aiKey)
	}

	if aiBaseURL, ok := config.CLI["ai_base_url"].(string); ok && aiBaseURL != "" {
		args = append(args, "-ai-base-url="+aiBaseURL)
	}

	if aiEndpoint, ok := config.CLI["ai_endpoint"].(string); ok && aiEndpoint != "" {
		args = append(args, "-ai-endpoint="+aiEndpoint)
	}

	if aiSkipSSL, ok := config.CLI["ai_skip_ssl"].(bool); ok && aiSkipSSL {
		args = append(args, "-ai-skip-ssl")
	}

	// Config file
	if conf, ok := config.CLI["conf"].(string); ok && conf != "" {
		args = append(args, "-conf="+conf)
	}

	// Additional options
	if excludeDir, ok := config.CLI["exclude_dir"].(string); ok && excludeDir != "" {
		args = append(args, "-exclude-dir="+excludeDir)
	}

	if log, ok := config.CLI["log"].(string); ok && log != "" {
		args = append(args, "-log="+log)
	}

	if sort, ok := config.CLI["sort"].(bool); ok && sort {
		args = append(args, "-sort")
	}

	if r, ok := config.CLI["r"].(bool); ok && r {
		args = append(args, "-r")
	}

	// Target path
	args = append(args, repoPath)
	return args, nil
}

// parseGosecFindings parses Gosec JSON output into findings
func ParseGosecFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	var gosecResult struct {
		Issues []struct {
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			RuleID     string `json:"rule_id"`
			Details    string `json:"details"`
			File       string `json:"file"`
			Code       string `json:"code"`
			Line        string `json:"line"`
		} `json:"Issues"`
	}

	if err := json.Unmarshal([]byte(output), &gosecResult); err != nil {
		return nil, err
	}

	for _, issue := range gosecResult.Issues {
		finding := models.Finding{
			ID:          fmt.Sprintf("gosec-%s-%s", issue.RuleID, filepath.Base(issue.File)),
			Title:       fmt.Sprintf("Gosec: %s", issue.Details),
			Description: issue.Details,
			Severity:    convertGosecSeverity(issue.Severity),
			Confidence:  convertGosecConfidence(issue.Confidence),
			File:        issue.File,
			CodeSnippet: issue.Code,
			Category:    "code",
			RuleID:      issue.RuleID,
			Tool:        "gosec",
			Tags:        []string{"code", "gosec", "golang", issue.RuleID},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// convertGosecSeverity converts Gosec severity to standard format
func convertGosecSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

// convertGosecConfidence converts Gosec confidence to standard format
func convertGosecConfidence(confidence string) string {
	switch strings.ToUpper(confidence) {
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}
package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildHadolintArgs builds command line arguments for Hadolint
func BuildHadolintArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Configuration file
	if configFile, ok := config.CLI["config"].(string); ok && configFile != "" {
		args = append(args, "-c", configFile)
	}

	// Output options
	if noFail, ok := config.CLI["no_fail"].(bool); ok && noFail {
		args = append(args, "--no-fail")
	}

	if noColor, ok := config.CLI["no_color"].(bool); ok && noColor {
		args = append(args, "--no-color")
	}

	if verbose, ok := config.CLI["verbose"].(bool); ok && verbose {
		args = append(args, "-V")
	}

	if format, ok := config.CLI["format"].(string); ok && format != "" && format != "tty" {
		args = append(args, "-f", format)
	}

	if filePathInReport, ok := config.CLI["file_path_in_report"].(string); ok && filePathInReport != "" {
		args = append(args, "--file-path-in-report", filePathInReport)
	}

	// Rule severity overrides
	if errors, ok := config.CLI["error"].([]interface{}); ok && len(errors) > 0 {
		for _, rule := range errors {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--error", ruleStr)
			}
		}
	}

	if warnings, ok := config.CLI["warning"].([]interface{}); ok && len(warnings) > 0 {
		for _, rule := range warnings {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--warning", ruleStr)
			}
		}
	}

	if infos, ok := config.CLI["info"].([]interface{}); ok && len(infos) > 0 {
		for _, rule := range infos {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--info", ruleStr)
			}
		}
	}

	if styles, ok := config.CLI["style"].([]interface{}); ok && len(styles) > 0 {
		for _, rule := range styles {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--style", ruleStr)
			}
		}
	}

	// Rule filtering
	if ignores, ok := config.CLI["ignore"].([]interface{}); ok && len(ignores) > 0 {
		for _, rule := range ignores {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--ignore", ruleStr)
			}
		}
	}

	// Trusted registries
	if registries, ok := config.CLI["trusted_registry"].([]interface{}); ok && len(registries) > 0 {
		for _, registry := range registries {
			if regStr, ok := registry.(string); ok {
				args = append(args, "--trusted-registry", regStr)
			}
		}
	}

	// Label requirements
	if labels, ok := config.CLI["require_label"].([]interface{}); ok && len(labels) > 0 {
		for _, label := range labels {
			if labelStr, ok := label.(string); ok {
				args = append(args, "--require-label", labelStr)
			}
		}
	}

	if strictLabels, ok := config.CLI["strict_labels"].(bool); ok && strictLabels {
		args = append(args, "--strict-labels")
	}

	// Pragmas
	if disableIgnorePragma, ok := config.CLI["disable_ignore_pragma"].(bool); ok && disableIgnorePragma {
		args = append(args, "--disable-ignore-pragma")
	}

	// Failure threshold
	if threshold, ok := config.CLI["failure_threshold"].(string); ok && threshold != "" {
		args = append(args, "-t", threshold)
	}

	// Input files - Dockerfiles to lint
	if dockerfiles, ok := config.CLI["dockerfiles"].([]interface{}); ok && len(dockerfiles) > 0 {
		for _, df := range dockerfiles {
			if dfStr, ok := df.(string); ok {
				args = append(args, dfStr)
			}
		}
	} else {
		// Default: look for Dockerfile in repo path
		args = append(args, fmt.Sprintf("%s/Dockerfile", repoPath))
	}

	return args, nil
}

// parseHadolintFindings parses Hadolint output into findings
func ParseHadolintFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// Hadolint supports multiple output formats. Try to parse JSON first
	var hadolintResult []struct {
		Code        string `json:"code"`
		Message     string `json:"message"`
		Level       string `json:"level"`
		File        string `json:"file"`
		Line         int    `json:"line"`
		Column      int    `json:"column"`
	}

	if err := json.Unmarshal([]byte(output), &hadolintResult); err == nil {
		for _, result := range hadolintResult {
			finding := models.Finding{
				ID:          fmt.Sprintf("hadolint-%s-%s-%d", result.Code, result.File, result.Line),
				Title:       fmt.Sprintf("Hadolint: %s", result.Code),
				Description: result.Message,
				Severity:    convertHadolintSeverity(result.Level),
				File:        result.File,
				Line:         result.Line,
				Column:      result.Column,
				Category:    "dockerfile",
				RuleID:      result.Code,
				Tool:        "hadolint",
				Tags:        []string{"hadolint", "dockerfile", result.Level, result.Code},
			}
			findings = append(findings, finding)
		}
		return findings, nil
	}

	// If JSON parsing fails, try to parse plain text output
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Hadolint plain text format: FILE:LINE CODE MESSAGE
		// Example: Dockerfile:5 DL3006 Always tag the version of an image explicitly
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 3 {
			location := parts[0] // FILE:LINE
			code := parts[1]     // DL3006
			message := parts[2]  // Always tag the version...

			// Parse location
			var file string
			var lineNum int
			if strings.Contains(location, ":") {
				locParts := strings.Split(location, ":")
				if len(locParts) >= 2 {
					file = locParts[0]
					fmt.Sscanf(locParts[1], "%d", &lineNum)
				}
			}

			finding := models.Finding{
				ID:          fmt.Sprintf("hadolint-%s-%s-%d", code, file, lineNum),
				Title:       fmt.Sprintf("Hadolint: %s", code),
				Description: message,
				Severity:    "medium", // Default for plain text parsing
				File:        file,
				Line:         lineNum,
				Category:    "dockerfile",
				RuleID:      code,
				Tool:        "hadolint",
				Tags:        []string{"hadolint", "dockerfile", code},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// convertHadolintSeverity converts Hadolint severity to standard format
func convertHadolintSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	case "INFO":
		return "low"
	case "STYLE":
		return "info"
	default:
		return "medium"
	}
}
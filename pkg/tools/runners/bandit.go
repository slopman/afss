package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildBanditArgs builds command line arguments for Bandit
func BuildBanditArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Recursive scanning
	if recursive, ok := config.CLI["recursive"].(bool); ok && recursive {
		args = append(args, "-r")
	}

	// Aggregation mode
	if aggregate, ok := config.CLI["aggregate"].(string); ok && aggregate != "" && aggregate != "vuln" {
		args = append(args, "-a", aggregate)
	}

	// Context lines
	if number, ok := config.CLI["number"].(int); ok && number > 0 {
		args = append(args, "-n", fmt.Sprintf("%d", number))
	}

	// Config file
	if configfile, ok := config.CLI["configfile"].(string); ok && configfile != "" {
		args = append(args, "-c", configfile)
	}

	// Profile
	if profile, ok := config.CLI["profile"].(string); ok && profile != "" {
		args = append(args, "-p", profile)
	}

	// Tests to run
	if tests, ok := config.CLI["tests"].(string); ok && tests != "" {
		args = append(args, "-t", tests)
	}

	// Tests to skip
	if skips, ok := config.CLI["skips"].(string); ok && skips != "" {
		args = append(args, "-s", skips)
	}

	// Severity level
	if severityLevel, ok := config.CLI["severity_level"].(string); ok && severityLevel != "" && severityLevel != "all" {
		args = append(args, "--severity-level", severityLevel)
	}

	// Confidence level
	if confidenceLevel, ok := config.CLI["confidence_level"].(string); ok && confidenceLevel != "" && confidenceLevel != "all" {
		args = append(args, "--confidence-level", confidenceLevel)
	}

	// Output format (must pass -f json when format is json; previous logic skipped it)
	if format, ok := config.CLI["format"].(string); ok && format != "" {
		args = append(args, "-f", format)
	}

	// Message template
	if msgTemplate, ok := config.CLI["msg_template"].(string); ok && msgTemplate != "" {
		args = append(args, "--msg-template", msgTemplate)
	}

	// Output file
	if outputFile, ok := config.CLI["output_file"].(string); ok && outputFile != "" {
		args = append(args, "-o", outputFile)
	}

	// Verbosity options
	if verbose, ok := config.CLI["verbose"].(bool); ok && verbose {
		args = append(args, "-v")
	}

	if debug, ok := config.CLI["debug"].(bool); ok && debug {
		args = append(args, "-d")
	}

	if quiet, ok := config.CLI["quiet"].(bool); ok && quiet {
		args = append(args, "-q")
	}

	// Ignore nosec comments
	if ignoreNosec, ok := config.CLI["ignore_nosec"].(bool); ok && ignoreNosec {
		args = append(args, "--ignore-nosec")
	}

	// Excluded paths (YAML uses "exclude"; older configs used "excluded_paths")
	if excludedPaths, ok := config.CLI["excluded_paths"].(string); ok && excludedPaths != "" {
		args = append(args, "-x", excludedPaths)
	} else if exclude, ok := config.CLI["exclude"].(string); ok && exclude != "" {
		args = append(args, "-x", exclude)
	}

	// Baseline
	if baseline, ok := config.CLI["baseline"].(string); ok && baseline != "" {
		args = append(args, "-b", baseline)
	}

	// INI path
	if iniPath, ok := config.CLI["ini_path"].(string); ok && iniPath != "" {
		args = append(args, "--ini", iniPath)
	}

	// Exit zero
	if exitZero, ok := config.CLI["exit_zero"].(bool); ok && exitZero {
		args = append(args, "--exit-zero")
	}

	// Target paths
	if targets, ok := config.CLI["targets"].([]interface{}); ok && len(targets) > 0 {
		for _, target := range targets {
			if targetStr, ok := target.(string); ok {
				args = append(args, targetStr)
			}
		}
	} else {
		// Default to repo path
		args = append(args, repoPath)
	}

	return args, nil
}

// parseBanditFindings parses Bandit JSON output into findings
func ParseBanditFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// Bandit JSON structure
	var banditResult struct {
		Errors   []struct {
			Filename  string `json:"filename"`
			Reason    string `json:"reason"`
			Traceback string `json:"traceback"`
		} `json:"errors"`
		GeneratedAt string `json:"generated_at"`
		Metrics     struct {
			ConfidenceHighCount   int `json:"CONFIDENCE.HIGH"`
			ConfidenceLowCount    int `json:"CONFIDENCE.LOW"`
			ConfidenceMediumCount int `json:"CONFIDENCE.MEDIUM"`
			ConfidenceUndefinedCount int `json:"CONFIDENCE.UNDEFINED"`
			SeverityHighCount     int `json:"SEVERITY.HIGH"`
			SeverityLowCount      int `json:"SEVERITY.LOW"`
			SeverityMediumCount   int `json:"SEVERITY.MEDIUM"`
			SeverityUndefinedCount int `json:"SEVERITY.UNDEFINED"`
			TotalLines            int `json:"_totals"`
		} `json:"metrics"`
		Results []struct {
			Code         string `json:"code"`
			Filename     string `json:"filename"`
			IssueConfidence string `json:"issue_confidence"`
			IssueSeverity string `json:"issue_severity"`
			IssueText     string `json:"issue_text"`
			LineNumber    int    `json:"line_number"`
			LineRange     []int  `json:"line_range"`
			MoreInfo     string `json:"more_info"`
			TestID       string `json:"test_id"`
			TestName     string `json:"test_name"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(output), &banditResult); err == nil {
		for _, result := range banditResult.Results {
			finding := models.Finding{
				ID:          fmt.Sprintf("bandit-%s-%s-%d", result.TestID, result.Filename, result.LineNumber),
				Title:       fmt.Sprintf("Bandit: %s", result.TestName),
				Description: result.IssueText,
				Severity:    convertBanditSeverity(result.IssueSeverity),
				File:        result.Filename,
				Line:         result.LineNumber,
				CodeSnippet: result.Code,
				Category:    "code",
				RuleID:      result.TestID,
				Tool:        "bandit",
				Tags:        []string{"bandit", "python", result.IssueSeverity, result.IssueConfidence, result.TestID},
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

		// Bandit plain text format contains severity indicators
		if strings.Contains(line, "HIGH") || strings.Contains(line, "MEDIUM") || strings.Contains(line, "LOW") {
			finding := models.Finding{
				ID:          fmt.Sprintf("bandit-text-%d", len(findings)),
				Title:       "Bandit: Security issue found",
				Description: line,
				Severity:    "medium",
				Category:    "code",
				Tool:        "bandit",
				Tags:        []string{"bandit", "python", "plaintext"},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// convertBanditSeverity converts Bandit severity to standard format
func convertBanditSeverity(severity string) string {
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
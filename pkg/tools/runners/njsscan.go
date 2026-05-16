package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildNjsscanArgs builds command line arguments for Njsscan
func BuildNjsscanArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Output formats (choose one, default to JSON)
	if json, ok := config.CLI["json"].(bool); ok && json {
		args = append(args, "--json")
	}

	if sarif, ok := config.CLI["sarif"].(bool); ok && sarif {
		args = append(args, "--sarif")
	}

	if sonarqube, ok := config.CLI["sonarqube"].(bool); ok && sonarqube {
		args = append(args, "--sonarqube")
	}

	if html, ok := config.CLI["html"].(bool); ok && html {
		args = append(args, "--html")
	}

	// Output file
	if output, ok := config.CLI["output"].(string); ok && output != "" {
		args = append(args, "-o", output)
	}

	// Config file
	if configFile, ok := config.CLI["config"].(string); ok && configFile != "" {
		args = append(args, "-c", configFile)
	}

	// Missing controls check
	if missingControls, ok := config.CLI["missing_controls"].(bool); ok && missingControls {
		args = append(args, "--missing-controls")
	}

	// Exit warning
	if exitWarning, ok := config.CLI["exit_warning"].(bool); ok && exitWarning {
		args = append(args, "-w")
	}

	// Version (if requested)
	if version, ok := config.CLI["version"].(bool); ok && version {
		args = append(args, "--version")
	}

	// Target paths
	if paths, ok := config.CLI["paths"].([]interface{}); ok && len(paths) > 0 {
		for _, path := range paths {
			if pathStr, ok := path.(string); ok {
				args = append(args, pathStr)
			}
		}
	} else {
		// Default to repo path
		args = append(args, repoPath)
	}

	return args, nil
}

// parseNjsscanFindings parses Njsscan JSON output into findings
func ParseNjsscanFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// Njsscan JSON structure
	var njsscanResult struct {
		Errors []struct {
			Filename string `json:"filename"`
			Error    string `json:"error"`
		} `json:"errors"`
		Files map[string]struct {
			FileType string `json:"file_type"`
			Metadata map[string]interface{} `json:"metadata"`
			Findings map[string][]struct {
				Files       []struct {
					FilePath string `json:"file_path"`
					MatchLines []int `json:"match_lines"`
					MatchString string `json:"match_string"`
				} `json:"files"`
				Line       int    `json:"line"`
				Column    int    `json:"column"`
				Message   string `json:"message"`
				LineData   string `json:"line_data"`
				Severity  string `json:"severity"`
				Confidence string `json:"confidence"`
				Cwe       struct {
					ID  string `json:"id"`
					URL string `json:"url"`
				} `json:"cwe"`
				Tags       []string `json:"tags"`
				TestID     string   `json:"test_id"`
				TestName   string   `json:"test_name"`
				MoreInfo   string   `json:"more_info"`
			} `json:"findings"`
		} `json:"files"`
		Metadata struct {
			Timestamp string `json:"timestamp"`
			Version   string `json:"version"`
			NjsscanVersion string `json:"njsscan_version"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal([]byte(output), &njsscanResult); err == nil {
		for _, fileData := range njsscanResult.Files {
			for ruleID, ruleFindings := range fileData.Findings {
				for _, finding := range ruleFindings {
					finding := models.Finding{
						ID:          fmt.Sprintf("njsscan-%s-%s-%d", ruleID, finding.Files[0].FilePath, finding.Line),
						Title:       fmt.Sprintf("Njsscan: %s", finding.TestName),
						Description: finding.Message,
						Severity:    convertNjsscanSeverity(finding.Severity),
						File:        finding.Files[0].FilePath,
						Line:         finding.Line,
						CodeSnippet: finding.LineData,
						Category:    "code",
						RuleID:      ruleID,
						Tool:        "njsscan",
						Tags:        append(finding.Tags, "njsscan", "javascript", finding.Severity, finding.Confidence, ruleID),
					}
					findings = append(findings, finding)
				}
			}
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

		// Njsscan plain text format contains severity indicators
		if strings.Contains(line, "HIGH") || strings.Contains(line, "MEDIUM") || strings.Contains(line, "LOW") || strings.Contains(line, "INFO") {
			finding := models.Finding{
				ID:          fmt.Sprintf("njsscan-text-%d", len(findings)),
				Title:       "Njsscan: Security issue found",
				Description: line,
				Severity:    "medium",
				Category:    "code",
				Tool:        "njsscan",
				Tags:        []string{"njsscan", "javascript", "plaintext"},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// convertNjsscanSeverity converts Njsscan severity to standard format
func convertNjsscanSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "INFO":
		return "info"
	default:
		return "info"
	}
}
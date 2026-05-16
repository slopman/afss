package runners

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
	"github.com/security-scanner/afss-orchestrator/pkg/util"
)

// DefaultGitleaksReportPath is used when configs/tools/gitleaks.yaml does not set report_path.
// Gitleaks v8+ writes JSON/CSV/SARIF only to this file (-r); stdout is human logs, not the report.
const DefaultGitleaksReportPath = "/tmp/afss-gitleaks-report.json"

// GitleaksReportPath returns the configured report file path or DefaultGitleaksReportPath.
func GitleaksReportPath(config *models.ToolConfig) string {
	if p, ok := config.CLI["report_path"].(string); ok && p != "" {
		return p
	}
	return DefaultGitleaksReportPath
}

// GitleaksReportPathForRead resolves a path for os.ReadFile (relative paths are under repoPath).
func GitleaksReportPathForRead(config *models.ToolConfig, repoPath string) string {
	p := GitleaksReportPath(config)
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(repoPath, p)
}

// buildGitleaksArgs builds command line arguments for Gitleaks
func BuildGitleaksArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Command (default is detect)
	command := "detect"
	if cmd, ok := config.CLI["command"].(string); ok && cmd != "" {
		command = cmd
	}
	args = append(args, command)

	// Source path
	if source, ok := config.CLI["source"].(string); ok && source != "" {
		args = append(args, "-s", source)
	} else {
		args = append(args, "-s", repoPath)
	}

	// Configuration
	if configFile, ok := config.CLI["config"].(string); ok && configFile != "" {
		args = append(args, "-c", configFile)
	}

	if ignorePath, ok := config.CLI["gitleaks_ignore_path"].(string); ok && ignorePath != "" {
		args = append(args, "-i", ignorePath)
	}

	// Output options (always pass -f when format is set; default in YAML is json)
	if reportFormat, ok := config.CLI["report_format"].(string); ok && reportFormat != "" {
		args = append(args, "-f", reportFormat)
	}
	// v8+ requires -r for machine-readable report; stdout is not JSON.
	args = append(args, "-r", GitleaksReportPath(config))

	if verbose, ok := config.CLI["verbose"].(bool); ok && verbose {
		args = append(args, "-v")
	}

	if noBanner, ok := config.CLI["no_banner"].(bool); ok && noBanner {
		args = append(args, "--no-banner")
	}

	if noColor, ok := config.CLI["no_color"].(bool); ok && noColor {
		args = append(args, "--no-color")
	}

	if logLevel, ok := config.CLI["log_level"].(string); ok && logLevel != "" && logLevel != "info" {
		args = append(args, "-l", logLevel)
	}

	// Filtering and ignoring
	if baselinePath, ok := config.CLI["baseline_path"].(string); ok && baselinePath != "" {
		args = append(args, "-b", baselinePath)
	}

	if enableRules, ok := config.CLI["enable_rule"].([]interface{}); ok && len(enableRules) > 0 {
		for _, rule := range enableRules {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--enable-rule", ruleStr)
			}
		}
	}

	if ignoreGitleaksAllow, ok := config.CLI["ignore_gitleaks_allow"].(bool); ok && ignoreGitleaksAllow {
		args = append(args, "--ignore-gitleaks-allow")
	}

	// Git options
	if logOpts, ok := config.CLI["log_opts"].(string); ok && logOpts != "" {
		args = append(args, "--log-opts", logOpts)
	}

	if followSymlinks, ok := config.CLI["follow_symlinks"].(bool); ok && followSymlinks {
		args = append(args, "--follow-symlinks")
	}

	// Performance
	if maxTargetMB, ok := config.CLI["max_target_megabytes"].(int); ok && maxTargetMB > 0 {
		args = append(args, "--max-target-megabytes", fmt.Sprintf("%d", maxTargetMB))
	}

	// Security
	if redact, ok := config.CLI["redact"].(int); ok && redact >= 0 && redact <= 100 {
		args = append(args, "--redact", fmt.Sprintf("%d", redact))
	}

	// Exit behavior
	if exitCode, ok := config.CLI["exit_code"].(int); ok && exitCode >= 0 {
		args = append(args, "--exit-code", fmt.Sprintf("%d", exitCode))
	}

	return args, nil
}

// parseGitleaksFindings parses Gitleaks JSON output into findings
func ParseGitleaksFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	trim := strings.TrimSpace(output)
	if frag := util.FirstJSONValue(trim); frag != "" {
		trim = frag
	}
	// Gitleaks JSON structure
	var gitleaksResult []struct {
		Line       string `json:"line"`
		LineNumber int    `json:"lineNumber"`
		Offender  string `json:"offender"`
		Commit    string `json:"commit"`
		Repo      string `json:"repo"`
		RepoURL   string `json:"repoURL"`
		LeakURL   string `json:"leakURL"`
		Rule      string `json:"rule"`
		Tags      string `json:"tags"`
		File      string `json:"file"`
		Email     string `json:"email"`
		Author    string `json:"author"`
		Date      string `json:"date"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal([]byte(trim), &gitleaksResult); err == nil {
		for _, leak := range gitleaksResult {
			finding := models.Finding{
				ID:          fmt.Sprintf("gitleaks-%s-%s-%d", leak.Rule, leak.File, leak.LineNumber),
				Title:       fmt.Sprintf("Gitleaks: %s detected", leak.Rule),
				Description: fmt.Sprintf("Found %s in file %s at line %d", leak.Rule, leak.File, leak.LineNumber),
				Severity:    "high", // Secrets are always high severity
				File:        leak.File,
				Line:        leak.LineNumber,
				CodeSnippet: leak.Offender,
				Category:    "secret",
				RuleID:      leak.Rule,
				Tool:        "gitleaks",
				Tags:        []string{"gitleaks", "secret", leak.Rule},
			}

			// Add additional metadata if available
			if leak.Commit != "" {
				finding.Tags = append(finding.Tags, "commit:"+leak.Commit[:8])
			}
			if leak.Author != "" {
				finding.Tags = append(finding.Tags, "author:"+leak.Author)
			}

			findings = append(findings, finding)
		}
		return findings, nil
	}

	// Gitleaks v8+ JSON (array of objects with RuleID, Secret, File, StartLine, ...)
	var gitleaksV8 []struct {
		RuleID      string `json:"RuleID"`
		Secret      string `json:"Secret"`
		Match       string `json:"Match"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
		Description string `json:"Description"`
		Commit      string `json:"Commit"`
		Author      string `json:"Author"`
	}
	if err := json.Unmarshal([]byte(trim), &gitleaksV8); err == nil {
		for _, leak := range gitleaksV8 {
			snippet := leak.Secret
			if snippet == "" {
				snippet = leak.Match
			}
			finding := models.Finding{
				ID:          fmt.Sprintf("gitleaks-%s-%s-%d", leak.RuleID, leak.File, leak.StartLine),
				Title:       fmt.Sprintf("Gitleaks: %s detected", leak.RuleID),
				Description: leak.Description,
				Severity:    "high",
				File:        leak.File,
				Line:        leak.StartLine,
				CodeSnippet: snippet,
				Category:    "secret",
				RuleID:      leak.RuleID,
				Tool:        "gitleaks",
				Tags:        []string{"gitleaks", "secret", leak.RuleID},
			}
			if leak.Commit != "" && len(leak.Commit) >= 8 {
				finding.Tags = append(finding.Tags, "commit:"+leak.Commit[:8])
			}
			if leak.Author != "" {
				finding.Tags = append(finding.Tags, "author:"+leak.Author)
			}
			findings = append(findings, finding)
		}
		return findings, nil
	}

	// If JSON parsing fails, try to parse plain text output
	lines := strings.Split(strings.TrimSpace(trim), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Gitleaks plain text format contains "leak" or similar indicators
		if strings.Contains(line, "leak") || strings.Contains(line, "secret") {
			finding := models.Finding{
				ID:          fmt.Sprintf("gitleaks-text-%d", len(findings)),
				Title:       "Gitleaks: Potential secret found",
				Description: line,
				Severity:    "high",
				Category:    "secret",
				Tool:        "gitleaks",
				Tags:        []string{"gitleaks", "secret", "plaintext"},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
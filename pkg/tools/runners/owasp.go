package runners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// OwaspOutputDir returns the directory where dependency-check writes reports (-o),
// using the same rules as BuildOWASPDepCheckArgs. Relative paths are resolved under
// the orchestrator working directory so scans work with read-only repo mounts.
func OwaspOutputDir(config *models.ToolConfig, repoPath string) string {
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	outDir := filepath.Join(wd, "results", "owasp-dep-check")
	if o, ok := config.CLI["out"].(string); ok && o != "" {
		if filepath.IsAbs(o) {
			outDir = o
		} else {
			outDir = filepath.Join(wd, o)
		}
	} else if o, ok := config.CLI["output"].(string); ok && o != "" {
		if filepath.IsAbs(o) {
			outDir = o
		} else {
			outDir = filepath.Join(wd, o)
		}
	}
	return outDir
}

// OwaspDataDir returns the dependency-check --data directory (writable CVE DB).
func OwaspDataDir(config *models.ToolConfig) string {
	if d, ok := config.CLI["data"].(string); ok && d != "" {
		return d
	}
	return "/tmp/dependency-check-data"
}

// OwaspReportJSONPath is the standard JSON report path for the configured output directory.
func OwaspReportJSONPath(config *models.ToolConfig, repoPath string) string {
	return filepath.Join(OwaspOutputDir(config, repoPath), "dependency-check-report.json")
}

// buildOWASPDepCheckArgs builds command line arguments for OWASP Dependency Check
func BuildOWASPDepCheckArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Scan path — default to repository root (YAML often uses ".")
	scanArg := repoPath
	if scan, ok := config.CLI["scan"].(string); ok && scan != "" && scan != "." {
		if filepath.IsAbs(scan) {
			scanArg = scan
		} else {
			scanArg = filepath.Join(repoPath, scan)
		}
	}
	args = append(args, "-s", scanArg)

	// CVE/H2 data directory (must be writable in Docker; default under /tmp)
	args = append(args, "--data", OwaspDataDir(config))

	// Output format - Supported: HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL
	if format, ok := config.CLI["format"].(string); ok && format != "" {
		args = append(args, "-f", format)
	}

	// Pretty print JSON/XML output
	if prettyPrint, ok := config.CLI["prettyPrint"].(bool); ok && prettyPrint {
		args = append(args, "--prettyPrint")
	}

	// Output directory (YAML key is "out"; legacy "output" supported in OwaspOutputDir only for path helper)
	outDir := OwaspOutputDir(config, repoPath)
	args = append(args, "-o", outDir)

	// Exclude patterns - Ant-style patterns to exclude from scan
	if exclude, ok := config.CLI["exclude"].([]interface{}); ok && len(exclude) > 0 {
		for _, pattern := range exclude {
			if patternStr, ok := pattern.(string); ok {
				args = append(args, "--exclude", patternStr)
			}
		}
	}

	// Suppression files - XML files with vulnerability suppressions
	if suppression, ok := config.CLI["suppression"].([]interface{}); ok && len(suppression) > 0 {
		for _, file := range suppression {
			if fileStr, ok := file.(string); ok {
				args = append(args, "--suppression", fileStr)
			}
		}
	}

	// NVD API key - For faster database access
	if nvdApiKey, ok := config.CLI["nvdApiKey"].(string); ok && nvdApiKey != "" {
		args = append(args, "--nvdApiKey", nvdApiKey)
	}

	// Disable automatic NVD database updates (--noupdate / -n)
	if noupdate, ok := config.CLI["noupdate"].(bool); ok && noupdate {
		args = append(args, "--noupdate")
	} else if disableAutoUpdate, ok := config.CLI["disableAutoUpdate"].(bool); ok && disableAutoUpdate {
		args = append(args, "-n")
	}

	// Project name - Name shown in reports
	if project, ok := config.CLI["project"].(string); ok && project != "" {
		args = append(args, "--project", project)
	}

	// Fail on CVSS score - Exit with error if score >= threshold (0-10, 11=never fail)
	if v, ok := floatFromCLI(config.CLI["failOnCVSS"]); ok && v >= 0 {
		args = append(args, "--failOnCVSS", fmt.Sprintf("%.1f", v))
	}

	// JUnit failure threshold - CVSS score for JUnit report failures
	if v, ok := floatFromCLI(config.CLI["junitFailOnCVSS"]); ok && v >= 0 {
		args = append(args, "--junitFailOnCVSS", fmt.Sprintf("%.1f", v))
	}

	// Enable experimental analyzers
	if enableExperimental, ok := config.CLI["enableExperimental"].(bool); ok && enableExperimental {
		args = append(args, "--enableExperimental")
	}

	// Log file path - Write verbose logging to file
	if log, ok := config.CLI["log"].(string); ok && log != "" {
		args = append(args, "-l", log)
	}

	// Print advanced help message
	if advancedHelp, ok := config.CLI["advancedHelp"].(bool); ok && advancedHelp {
		args = append(args, "--advancedHelp")
	}

	// Download/update databases only, don't scan
	if updateonly, ok := config.CLI["updateonly"].(bool); ok && updateonly {
		args = append(args, "--updateonly")
	}

	return args, nil
}

func floatFromCLI(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	default:
		return 0, false
	}
}

// parseOWASPFindings parses OWASP Dependency Check JSON output into findings
func ParseOWASPFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// OWASP Dependency Check has complex JSON structure
	var owaspResult struct {
		ReportSchema string `json:"reportSchema"`
		ScanInfo       struct {
			EngineVersion string `json:"engineVersion"`
		} `json:"scanInfo"`
		ProjectInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"projectInfo"`
		Dependencies []struct {
			FileName        string `json:"fileName"`
			FilePath        string `json:"filePath"`
			Vulnerabilities []struct {
				Name        string  `json:"name"`
				Severity    string  `json:"severity"`
				CvssScore   float64 `json:"cvssScore"`
				Description string  `json:"description"`
				Cwe         string  `json:"cwe"`
			} `json:"vulnerabilities"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal([]byte(output), &owaspResult); err != nil {
		return nil, err
	}

	for _, dep := range owaspResult.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			finding := models.Finding{
				ID:          fmt.Sprintf("owasp-%s-%s", vuln.Name, dep.FileName),
				Title:       fmt.Sprintf("Vulnerability: %s", vuln.Name),
				Description: vuln.Description,
				Severity:    convertOWASPSeverity(vuln.Severity),
				File:        dep.FilePath,
				Category:    "dependency",
				RuleID:      vuln.Name,
				Tool:        "owasp-dep-check",
				Tags:        []string{"owasp", "dependency", "cve", vuln.Cwe},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// convertOWASPSeverity converts OWASP severity to standard format
func convertOWASPSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "MODERATE":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildOSVScannerArgs builds command line arguments for OSV-Scanner
func BuildOSVScannerArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Command and subcommand
	command := "scan"
	if cmd, ok := config.CLI["command"].(string); ok && cmd != "" {
		command = cmd
	}
	args = append(args, command)

	subcommand := "source"
	if sub, ok := config.CLI["subcommand"].(string); ok && sub != "" {
		subcommand = sub
	}
	args = append(args, subcommand)

	// Input sources
	if lockfiles, ok := config.CLI["lockfile"].([]interface{}); ok && len(lockfiles) > 0 {
		for _, lf := range lockfiles {
			if lfStr, ok := lf.(string); ok {
				args = append(args, "-L", lfStr)
			}
		}
	}

	if sboms, ok := config.CLI["sbom"].([]interface{}); ok && len(sboms) > 0 {
		for _, sbom := range sboms {
			if sbomStr, ok := sbom.(string); ok {
				args = append(args, "-S", sbomStr)
			}
		}
	}

	// Scanning options
	if recursive, ok := config.CLI["recursive"].(bool); ok && recursive {
		args = append(args, "-r")
	}

	if noIgnore, ok := config.CLI["no_ignore"].(bool); ok && noIgnore {
		args = append(args, "--no-ignore")
	}

	if includeGitRoot, ok := config.CLI["include_git_root"].(bool); ok && includeGitRoot {
		args = append(args, "--include-git-root")
	}

	// Data sources
	if dataSource, ok := config.CLI["data_source"].(string); ok && dataSource != "" && dataSource != "deps.dev" {
		args = append(args, "--data-source", dataSource)
	}

	if mavenRegistry, ok := config.CLI["maven_registry"].(string); ok && mavenRegistry != "" {
		args = append(args, "--maven-registry", mavenRegistry)
	}

	// Configuration
	if configFile, ok := config.CLI["config"].(string); ok && configFile != "" {
		args = append(args, "--config", configFile)
	}

	// Output options
	if format, ok := config.CLI["format"].(string); ok && format != "" {
		args = append(args, "-f", format)
	}

	if serve, ok := config.CLI["serve"].(bool); ok && serve {
		args = append(args, "--serve")
	}

	if port, ok := config.CLI["port"].(string); ok && port != "" && port != "8000" {
		args = append(args, "--port", port)
	}

	if output, ok := config.CLI["output"].(string); ok && output != "" {
		args = append(args, "--output", output)
	}

	// Verbosity
	if verbosity, ok := config.CLI["verbosity"].(string); ok && verbosity != "" && verbosity != "info" {
		args = append(args, "--verbosity", verbosity)
	}

	// Offline mode
	if offline, ok := config.CLI["offline"].(bool); ok && offline {
		args = append(args, "--offline")
	}

	if offlineVulns, ok := config.CLI["offline_vulnerabilities"].(bool); ok && offlineVulns {
		args = append(args, "--offline-vulnerabilities")
	}

	if downloadOffline, ok := config.CLI["download_offline_databases"].(bool); ok && downloadOffline {
		args = append(args, "--download-offline-databases")
	}

	// Analysis options
	if callAnalysis, ok := config.CLI["call_analysis"].([]interface{}); ok && len(callAnalysis) > 0 {
		for _, ca := range callAnalysis {
			if caStr, ok := ca.(string); ok {
				args = append(args, "--call-analysis", caStr)
			}
		}
	}

	if noCallAnalysis, ok := config.CLI["no_call_analysis"].([]interface{}); ok && len(noCallAnalysis) > 0 {
		for _, nca := range noCallAnalysis {
			if ncaStr, ok := nca.(string); ok {
				args = append(args, "--no-call-analysis", ncaStr)
			}
		}
	}

	if noResolve, ok := config.CLI["no_resolve"].(bool); ok && noResolve {
		args = append(args, "--no-resolve")
	}

	// Behavior options
	if allowNoLockfiles, ok := config.CLI["allow_no_lockfiles"].(bool); ok && allowNoLockfiles {
		args = append(args, "--allow-no-lockfiles")
	}

	if allPackages, ok := config.CLI["all_packages"].(bool); ok && allPackages {
		args = append(args, "--all-packages")
	}

	if allVulns, ok := config.CLI["all_vulns"].(bool); ok && allVulns {
		args = append(args, "--all-vulns")
	}

	// License scanning
	if licenses, ok := config.CLI["licenses"].(string); ok && licenses != "" {
		args = append(args, "--licenses", licenses)
	}

	// Experimental features
	if deprecatedPkgs, ok := config.CLI["experimental_flag_deprecated_packages"].(bool); ok && deprecatedPkgs {
		args = append(args, "--experimental-flag-deprecated-packages")
	}

	if expPlugins, ok := config.CLI["experimental_plugins"].([]interface{}); ok && len(expPlugins) > 0 {
		for _, plugin := range expPlugins {
			if pluginStr, ok := plugin.(string); ok {
				args = append(args, "--experimental-plugins", pluginStr)
			}
		}
	}

	if expDisablePlugins, ok := config.CLI["experimental_disable_plugins"].([]interface{}); ok && len(expDisablePlugins) > 0 {
		for _, plugin := range expDisablePlugins {
			if pluginStr, ok := plugin.(string); ok {
				args = append(args, "--experimental-disable-plugins", pluginStr)
			}
		}
	}

	if expNoDefaultPlugins, ok := config.CLI["experimental_no_default_plugins"].(bool); ok && expNoDefaultPlugins {
		args = append(args, "--experimental-no-default-plugins")
	}

	// Target directories
	if directories, ok := config.CLI["directories"].([]interface{}); ok && len(directories) > 0 {
		for _, dir := range directories {
			if dirStr, ok := dir.(string); ok {
				args = append(args, dirStr)
			}
		}
	} else {
		// Default to repo path
		args = append(args, repoPath)
	}

	return args, nil
}

// parseOSVScannerFindings parses OSV-Scanner JSON output into findings
func ParseOSVScannerFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// OSV-Scanner JSON structure
	var osvResult []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID   string `json:"id"`
				Summary string `json:"summary"`
				DatabaseSpecific struct {
					CVSS struct {
						Score float64 `json:"score"`
					} `json:"cvss"`
					Severity string `json:"severity"`
				} `json:"database_specific"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	}

	if err := json.Unmarshal([]byte(output), &osvResult); err == nil {
		for _, source := range osvResult {
			for _, pkg := range source.Packages {
				for _, vuln := range pkg.Vulnerabilities {
					finding := models.Finding{
						ID:          fmt.Sprintf("osv-%s-%s-%s", vuln.ID, pkg.Package.Name, pkg.Package.Version),
						Title:       fmt.Sprintf("OSV: %s", vuln.ID),
						Description: vuln.Summary,
						Severity:    convertOSVSeverity(vuln.DatabaseSpecific.Severity),
						File:        source.Source.Path,
						Category:    "vulnerability",
						RuleID:      vuln.ID,
						Tool:        "osv-scanner",
						Tags:        []string{"osv", "vulnerability", pkg.Package.Ecosystem, vuln.ID},
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

		// OSV-Scanner plain text format contains vulnerability indicators
		if strings.Contains(line, "vulnerability") || strings.Contains(line, "VULN") {
			finding := models.Finding{
				ID:          fmt.Sprintf("osv-text-%d", len(findings)),
				Title:       "OSV-Scanner: Vulnerability found",
				Description: line,
				Severity:    "high",
				Category:    "vulnerability",
				Tool:        "osv-scanner",
				Tags:        []string{"osv", "vulnerability", "plaintext"},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// convertOSVSeverity converts OSV severity to standard format
func convertOSVSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}